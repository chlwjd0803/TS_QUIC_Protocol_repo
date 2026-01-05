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
static inline path_metric_t compute_metric_safe(picoquic_path_t* p)
{
    path_metric_t M = {0};

    /* 1. 경로 유효성 검사: 검증 전이거나 무효한 경우 BAD 등급 부여 */
    if (!p || !p->first_tuple || !p->first_tuple->challenge_verified) {
        M.grade = 2; // 검증 전/무효 path는 BAD
        return M;
    }

    /* 2. RTT 계산 및 EWMA(지수 이동 평균) 적용 */
    /* Smoothed RTT가 없으면 기본값으로 9999ms 설정 */
    double rtt_ms = (p->smoothed_rtt > 0 ? p->smoothed_rtt / 1000.0 : 9999.0);
    
    static double ewma[16] = {0};
    double a = 0.2; // 보정 계수
    int pid = (int)(p->unique_path_id % 16);

    /* 지수 이동 평균 계산 (급격한 변화 억제) */
    if (ewma[pid] < 0.5) 
        ewma[pid] = rtt_ms;
    else 
        ewma[pid] = a * rtt_ms + (1 - a) * ewma[pid];

    M.rtt_ms = ewma[pid];

    /* 3. Loss Rate(손실률) 계산 */
    uint64_t delivered = (p->delivered > 0 ? p->delivered : 1);
    double loss_pct = 0.0;

    /* 전달된 바이트 대비 손실 바이트 비율 계산 */
    if (p->total_bytes_lost > 0 && p->total_bytes_lost < delivered)
        loss_pct = (double)p->total_bytes_lost * 100.0 / (double)delivered;
    else if (p->total_bytes_lost >= delivered)
        loss_pct = 50.0; // 비정상 상황 가드

    M.loss_rate = loss_pct;

    /* 4. 메트릭 기반 등급 판정 (0:GOOD, 1:WARN, 2:BAD) */
    if (M.rtt_ms > 250.0 || M.loss_rate > 10.0)      
        M.grade = 2; // BAD
    else if (M.rtt_ms > 120.0 || M.loss_rate > 3.0)  
        M.grade = 1; // WARN
    else                                             
        M.grade = 0; // GOOD

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
    /* 체류 시간(Dwell Time) 및 마진 파라미터 */
    const uint64_t DWELL_FAILOVER = 200000;  // 200 ms (Failover 유지)
    const uint64_t DWELL_FAILBACK = 400000;  // 400 ms (Failback 유지)
    const double   RTT_MARGIN_MS  = 20.0;    // 스위칭을 위한 최소 RTT 이득

    int lp = *last_primary;
    uint64_t dt = now - *last_switch_time;

    /* 1) 초기화 상태: WLAN(Wi-Fi) 우선 선택 */
    if (lp < 0) {
        *last_primary   = wlan_id;
        *last_switch_time = now;
        return wlan_id;
    }

    /* 2) 예외 처리: 사용 가능한 경로가 전혀 없는 경우 */
    if (wlan_id < 0 && usb_id < 0) return lp;

    /* 3) 상태 판정: 둘 다 BAD면 기존 경로 유지(전환 이득 없음) */
    int both_bad = (WLAN && USB && (WLAN->grade == 2 && USB->grade == 2));

    /* ---- A) 현재 WLAN이 주 경로인 경우 ---- */
    if (lp == wlan_id) {
        if (dt < DWELL_FAILOVER) return wlan_id; // 최소 유지 시간 미달
        if (both_bad) return wlan_id;

        /* FAILOVER 조건: WLAN은 나쁜데 USB는 쓸만할 때 */
        if (WLAN->grade == 2 && USB && USB->grade != 2) {
            *last_primary = usb_id; *last_switch_time = now;
            return usb_id;
        }
        
        /* WLAN이 WARN인데 USB가 GOOD인 경우 전환 */
        if (WLAN->grade == 1 && USB && USB->grade == 0) {
            *last_primary = usb_id; *last_switch_time = now;
            return usb_id;
        }

        /* 등급이 같더라도 USB의 RTT 이득이 확실할 때 전환 */
        if (USB && WLAN->grade == USB->grade &&
            (WLAN->rtt_ms - USB->rtt_ms) > RTT_MARGIN_MS)
        {
            *last_primary = usb_id; *last_switch_time = now;
            return usb_id;
        }
        
        return wlan_id;
    }

    /* ---- B) 현재 USB가 주 경로인 경우 ---- */
    if (lp == usb_id) {
        if (dt < DWELL_FAILBACK) return usb_id; // 최소 유지 시간 미달

        /* FAILBACK 조건: WLAN 상태가 복구(GOOD or WARN)되면 복귀 */
        if (WLAN && WLAN->grade <= 1) {
            *last_primary = wlan_id; *last_switch_time = now;
            return wlan_id;
        }

        /* 등급이 같을 때 WLAN이 더 빠르면 복귀 */
        if (WLAN && USB &&
            WLAN->grade == USB->grade &&
            (USB->rtt_ms - WLAN->rtt_ms) > (RTT_MARGIN_MS + 10.0))
        {
            *last_primary = wlan_id; *last_switch_time = now;
            return wlan_id;
        }
        
        return usb_id;
    }

    /* ---- C) 기타 예외 상황: 유효한 경로 아무거나 선택 ---- */
    *last_primary = (wlan_id >= 0 ? wlan_id : usb_id);
    *last_switch_time = now;
    return *last_primary;
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
        
    // LOGF("[PICK] METRIC WLAN grade=%d", Mwlan.grade);
    // LOGF("[PICK] METRIC USB  grade=%d", Musb.grade);
        
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