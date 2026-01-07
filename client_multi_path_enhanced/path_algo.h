#ifndef PATH_ALGO_H
#define PATH_ALGO_H

#include "picoquic.h"
#include "struct_type.h"
#include "net_tools.h"
#include "quic_helpers.h"
#include <math.h>

/* ============================================================
 * [1] 내부 로직 및 메트릭 계산 함수
 * ============================================================ */

/**
 * @brief 특정 경로의 품질 메트릭(RTT, Loss)을 계산하고 등급을 판정합니다.
 */
static inline path_metric_t compute_metric_safe(picoquic_path_t* p) {
    path_metric_t M = {0};
    
    /* 1. 객체가 아예 없으면 어쩔 수 없이 사망 */
    if (!p || !p->first_tuple) { 
        M.grade = 2; 
        return M; 
    }

    uint64_t now = picoquic_get_quic_time(p->cnx);

    /* 2. [복구됨] Verified 체크 + 좀비 방지 로직 
     * - 와이파이를 꺼도 즉시 Grade 2로 죽이지 않습니다.
     * - 5초(5,000,000us) 동안은 Grade 1(WARN) 상태로 유지하며 FSM이 자연스럽게 넘어가도록 합니다.
     * - 이렇게 해야 "2 -> 1 -> 2"로 널뛰기하는 현상이 사라집니다.
     */
    if (!p->first_tuple->challenge_verified) {
        
        uint64_t silence_duration = now - p->last_packet_received_at;

        /* 2초 이상 데이터 수신이 없고 검증도 안 된 상태라면 확실하게 사망 판정(Grade 2) */
        if (silence_duration > 2000000) { 
            M.grade = 2;   /* <--- 핵심 수정: Grade 1 -> Grade 2로 변경 */
            M.rtt_ms = 10000.0; /* RTT도 매우 크게 설정 */
        } else {
            /* 2초 이내의 일시적 검증 실패는 1등급 유지 (재시도 기회 부여) */
            M.grade = 1; 
            M.rtt_ms = 200.0;
        }
        
        return M;
    }

    /* 3. 정상 경로 RTT 평가 */
    double rtt_ms = (p->smoothed_rtt > 0 ? p->smoothed_rtt / 1000.0 : 50.0);
    M.rtt_ms = rtt_ms;

    /* RTT 기준 등급 판정 */
    if (rtt_ms > 3000.0) {
        M.grade = 2;       // 3초 이상 지연되면 BAD
    } else if (rtt_ms > 200.0) {
        M.grade = 1;       // 200ms 이상이면 WARN
    } else {
        M.grade = 0;       // 그 외엔 GOOD
    }

    return M;
}

/**
 * @brief 유한 상태 기계(FSM)를 사용하여 최종 주 경로를 선택합니다.
 */
static inline int fsm_pick(
    const path_metric_t* WLAN,
    const path_metric_t* USB,
    int wlan_id, int usb_id,
    int* last_primary,
    uint64_t now,
    uint64_t* last_switch_time
){
    int lp = *last_primary;

    /* 1. 와이파이가 살아있으면(Grade 0 or 1) 무조건 와이파이 */
    if (wlan_id >= 0 && WLAN && WLAN->grade < 2) {
        if (lp != wlan_id) {
            *last_primary = wlan_id;
            *last_switch_time = now;
        }
        return wlan_id; 
    }

    /* 2. 와이파이가 죽었으면? 핫스팟이 존재하기만 하면 무조건 선택 (등급 무시) */
    if (usb_id >= 0) { // <-- USB && USB->grade 조건 제거함
        if (lp != usb_id) {
            *last_primary = usb_id;
            *last_switch_time = now;
        }
        return usb_id;
    }

    /* 3. 둘 다 없으면 기존 유지 */
    return lp;
}


/* ============================================================
 * [2] 공개 함수 인터페이스
 * ============================================================ */

/**
 * @brief 현재 검증된 경로들 중에서 최적의 주 경로 인덱스를 반환합니다.
 */
static inline int pick_primary_idx(
    picoquic_cnx_t* c,
    pathsel_t* sel,
    int sc,
    uint32_t ip_wlan_be,
    uint32_t ip_usb_be,
    int* last_primary,
    uint64_t now,
    uint64_t* last_switch_time
){
    if (sc <= 0) return -1;
    
    int wlan_idx = -1, usb_idx = -1;
    
    /* 1. 사용 가능한 후보군 중 WLAN과 USB 경로 식별 */
    for (int i = 0; i < sc; i++) {
        picoquic_path_t* p = sel[i].p;
        picoquic_tuple_t* t = p->first_tuple;
        struct sockaddr_in* la = (struct sockaddr_in*)&t->local_addr;
        uint32_t local_ip_be = la->sin_addr.s_addr;

        if (local_ip_be == ip_wlan_be) wlan_idx = i;
        if (local_ip_be == ip_usb_be)  usb_idx = i;
    }

    picoquic_path_t* WLAN = (wlan_idx >= 0 ? sel[wlan_idx].p : NULL);
    picoquic_path_t* USB  = (usb_idx >= 0 ? sel[usb_idx].p : NULL);

    if (!WLAN && !USB) return *last_primary;

    /* 2. 각 경로의 메트릭 계산 */
    path_metric_t Mwlan = WLAN ? compute_metric_safe(WLAN) : (path_metric_t){ .grade = 2 };
    path_metric_t Musb  = USB  ? compute_metric_safe(USB)  : (path_metric_t){ .grade = 2 };
        
    LOGF("[PICK] METRIC WLAN grade=%d", Mwlan.grade);
    LOGF("[PICK] METRIC USB  grade=%d", Musb.grade);
        
    int wlan_id = (wlan_idx >= 0 ? sel[wlan_idx].idx : -1);
    int usb_id  = (usb_idx >= 0 ? sel[usb_idx].idx : -1);

    /* 3. FSM을 통한 최종 선택 */
    int pr = fsm_pick(&Mwlan, &Musb, wlan_id, usb_id,
                      last_primary, now, last_switch_time);
    
    LOGF("[PICK] fsm_pick -> primary=%d", pr);
    return pr;
}

/**
 * @brief 중복되지 않고 검증 완료된 유효 경로 리스트를 생성합니다.
 */
static inline void build_unique_verified_paths(picoquic_cnx_t* c, pathsel_t* sel, int* sc_io)
{
    int sc = 0;
    for (int i = 0; i < c->nb_paths; i++) {
        picoquic_path_t* p = c->path[i];
        if (!p || !p->first_tuple) continue;
        if (!path_verified_ptr(p)) continue;

        struct sockaddr_in* la = (struct sockaddr_in*)&p->first_tuple->local_addr;
        if (la->sin_family != AF_INET) continue;

        uint32_t ip_be = la->sin_addr.s_addr;
        
        /* 중복 IP(로컬 주소) 체크 */
        int is_dup = 0;
        for (int k = 0; k < sc; k++) {
            if (sel[k].ip_be == ip_be) { is_dup = 1; break; }
        }
        if (is_dup) continue;

        /* 유효 리스트에 추가 */
        sel[sc].idx   = i;
        sel[sc].ip_be = ip_be;
        sel[sc].p     = p;
        sc++;
    }
    *sc_io = sc;
}

/**
 * @brief 원하는 인덱스가 유효하지 않을 경우 검증된 아무 경로로나 폴백합니다.
 */
static inline int choose_verified_or_fallback(picoquic_cnx_t* c, int want_idx)
{
    if (want_idx >= 0 && want_idx < c->nb_paths) {
        picoquic_path_t* p = c->path[want_idx];
        if (p && p->first_tuple && p->first_tuple->challenge_verified)
            return want_idx;
    }

    /* 모든 경로를 순회하여 검증된 첫 번째 경로 선택 */
    for (int i = 0; i < c->nb_paths; i++) {
        picoquic_path_t* p = c->path[i];
        if (p && p->first_tuple && p->first_tuple->challenge_verified)
            return i;
    }
    
    /* 최후의 보루: 0번 경로 확인 */
    if (c->nb_paths > 0 && c->path[0] && c->path[0]->first_tuple &&
        c->path[0]->first_tuple->challenge_verified)
        return 0;

    return -1;
}

/**
 * @brief 특정 경로에 대해 새로운 챌린지를 전송하여 검증을 재시작합니다.
 */
static inline void kick_path_verification(picoquic_cnx_t* c, tx_t* st, int i)
{
    (void)st;
    picoquic_path_t* p = c->path[i];
    if (!p || !p->first_tuple) return;
    picoquic_set_path_challenge(c, i, picoquic_current_time());
}

#endif