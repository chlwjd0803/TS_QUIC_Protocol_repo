#ifndef QUIC_HELPERS_H
#define QUIC_HELPERS_H

#include "default_header.h"
#include "struct_type.h"
#include "net_tools.h"

/* ============================================================
 * [1] 기본 헬퍼 함수들 (경로 및 스트림 식별)
 * ============================================================ */

/**
 * @brief 클라이언트용 단방향 스트림 ID를 생성합니다.
 * 권장되는 경로별 고유 uni-stream sid 규칙: 2 + 4*i
 */
static inline uint64_t make_client_uni_sid_from_index(int i){
    return 2ull + 4ull * (uint64_t)i;
}

/**
 * @brief 경로 인덱스가 유효하고 주소 정보(tuple)가 존재하는지 확인합니다.
 * "실제로 쓸 수 있는 경로"인지 기초적인 상태를 체크합니다.
 */
static inline int path_ok(picoquic_cnx_t* c, int i){
    return (c && i >= 0 && i < (int)c->nb_paths && 
            c->path[i] && c->path[i]->first_tuple);
}

/**
 * @brief 연결(cnx) 객체에서 특정 인덱스의 경로 객체 포인터를 안전하게 가져옵니다.
 */
static inline picoquic_path_t* px_get_path(picoquic_cnx_t* c, int i) {
#if defined(HAVE_PICOQUIC_GET_PATH) 
    return picoquic_get_path(c, i);
#else
    return (c && i >= 0 && i < (int)c->nb_paths) ? c->path[i] : NULL;
#endif
}

/**
 * @brief 해당 경로가 Address Validation(Challenge)을 완료했는지 확인합니다.
 */
static inline int verified(picoquic_cnx_t* c, int i){
    if(!c || i<0 || i>= (int)c->nb_paths) return 0;
    
    picoquic_path_t* p = px_get_path(c, i);
    return (p && p->first_tuple && p->first_tuple->challenge_verified);
}


/* ============================================================
 * [2] 상태 체크 및 연결 관리 로직
 * ============================================================ */

/**
 * @brief QUIC 핸드셰이크가 완료되어 데이터 전송이 가능한 상태인지 확인합니다.
 */
static inline int hs_done(picoquic_cnx_t* cnx) {
    if (!cnx) return 0;
    
    picoquic_state_enum s = picoquic_get_cnx_state(cnx);
    
    /* 클라이언트 준비 완료 또는 데이터 송수신 가능 상태 체크 */
    if (s == picoquic_state_client_ready_start || s == picoquic_state_ready)
        return 1;
        
    /* 핸드셰이크가 종료되었고 1-RTT 패킷이 오갔는지 확인 */
    if (cnx->is_handshake_finished && (cnx->is_1rtt_received || cnx->is_1rtt_acked))
        return 1;
        
    return 0;
}

/**
 * @brief 연결이 Ready 상태 계열인지 확인합니다.
 */
static inline int cnx_is_ready_like(picoquic_cnx_t* c) {
    if (!c) return 0;
    
    picoquic_state_enum s = picoquic_get_cnx_state(c);
    
    if (s == picoquic_state_ready) return 1;
    
#ifdef picoquic_state_client_ready
    if (s == picoquic_state_client_ready) return 1;
#endif

#ifdef picoquic_state_client_ready_start
    if (s == picoquic_state_client_ready_start) return 1;
#endif

#ifdef picoquic_state_server_ready
    if (s == picoquic_state_server_ready) return 1;
#endif

#ifdef picoquic_state_server_false_start
    if (s == picoquic_state_server_false_start) return 1;
#endif

    return 0;
}

/**
 * @brief 1-RTT 암호화 키가 가용하여 실제 애플리케이션 데이터를 보낼 수 있는지 확인합니다.
 */
static inline int cnx_has_1rtt_keys(picoquic_cnx_t* c) {
#ifdef crypto_context
    return c && (c->crypto_context[picoquic_epoch_1rtt].aead_encrypt != NULL);
#else
    /* 구버전 대비 fallback */
    return cnx_is_ready_like(c);
#endif
}

/**
 * @brief 대역폭 조절(Pacing)에 의해 송신이 제한될 경우 권장 시간만큼 대기(usleep)합니다.
 */
static inline void wait_pace(picoquic_cnx_t* c, picoquic_path_t* p){
    if(!c || !p) return;
    
    uint64_t now = picoquic_current_time(), next = now;
    
    while(!picoquic_is_sending_authorized_by_pacing(c, p, now, &next)){
        if(next > now){
            useconds_t us = (useconds_t)(next - now);
            if(us > 0) usleep(us);
        }
        now = picoquic_current_time();
    }
}

/**
 * @brief 특정 인덱스의 경로가 송신에 적합한(정상) 상태인지 상세 검사합니다.
 */
static inline int path_verified_idx(picoquic_cnx_t* c, int i){
    if (!c || i < 0 || i >= c->nb_paths) return 0;
    
    picoquic_path_t* p = c->path[i];
    if (!p || !p->first_tuple) return 0;
    
    /* 초기화 및 검증 여부 확인 */
    if (!c->initial_validated) return 0;
    if (!p->rtt_is_initialized && p->last_packet_received_at == 0) return 0;
    
    /* 폐기되었거나 버려진 경로인지 확인 */
    if (p->path_is_demoted) return 0;
    if (p->path_abandon_sent || p->path_abandon_received) return 0;
    
    /* PTO가 필요하지만 전송 중인 바이트가 없는 특수 상황 가드 */
    if (p->is_pto_required && p->bytes_in_transit == 0) {
        return 0;
    }
    
    return 1;
}

/**
 * @brief 포인터를 통해 해당 경로의 챌린지 검증 여부를 확인합니다.
 */
static inline int path_verified_ptr(picoquic_path_t* p){
    return (p && p->first_tuple && p->first_tuple->challenge_verified);
}

/**
 * @brief 실제 데이터 송신 전, 경로의 건전성(Sane)을 최종 확인합니다.
 */
static inline int path_sane_for_send(picoquic_cnx_t* c, int i) {
    if (!c || i < 0 || i >= (int)c->nb_paths) return 0;
    
    picoquic_path_t* p = c->path[i];
    if (!p || !p->first_tuple) return 0;
    
    /* 주소 검증 완료 여부 */
    if (!p->first_tuple->challenge_verified) return 0;
    
    /* 경로가 활성 상태인지 확인 */
    if (p->path_abandon_sent || p->path_abandon_received) return 0;
    if (p->path_is_demoted) return 0;
    
    /* RTT 정보가 최소한으로 존재하는지 확인 */
    if (!p->rtt_is_initialized && p->last_packet_received_at == 0) return 0;
    
    return 1;
}

/**
 * @brief 0번 경로가 정상이 아닐 경우, 살아있는 다른 경로와 교체하여 통신을 유지합니다.
 */
static inline void ensure_path0_alive(picoquic_cnx_t* c){
    if (c == NULL) return;
    if (path_ok(c, 0)) return;              
    
    for (int i = 1; i < (int)c->nb_paths; i++){
        if (path_ok(c, i)) {
            picoquic_path_t* tmp = c->path[0];
            c->path[0] = c->path[i];
            c->path[i] = tmp;
            return;
        }
    }
}

/**
 * @brief 특정 경로 전용 스트림을 개설하고 경로 선호도(Affinity)를 설정합니다.
 */
static inline int ensure_stream_for_path(picoquic_cnx_t* c, void* app_ctx,
                           uint64_t* p_sid, int path_idx)
{
    if (!p_sid) return -1;

    /* sid가 없으면 인덱스에 기반하여 생성 */
    if (*p_sid == 0) {
        *p_sid = make_client_uni_sid_from_index(path_idx);
    }

    picoquic_path_t* p = c->path[path_idx];
    if (!p) return -1;

    /* 스트림이 특정 경로로만 나가도록 고정 */
    picoquic_set_stream_path_affinity(c, *p_sid, p->unique_path_id);

    /* 스트림 개설을 위한 더미 바이트 전송 */
    uint8_t dummy = 0xEE;
    return picoquic_add_to_stream_with_ctx(c, *p_sid, &dummy, 1, 0, app_ctx);
}

/**
 * @brief 특정 경로로 헤더와 페이로드를 안전하게 전송합니다. Affinity 재보증을 포함합니다.
 */
static int send_on_path_safe(picoquic_cnx_t* c, tx_t* st, int k,
                             const uint8_t* hdr, size_t hlen,
                             const uint8_t* payload, size_t plen)
{
    /* 1. 경로 상태 확인 */
    if (!path_sane_for_send(c, k)) return -1;

    picoquic_path_t* p = c->path[k];
    uint64_t sid = st->sid_per_path[k];
    
    /* 2. 스트림 존재 여부 확인 및 생성 */
    if (sid == 0) {
        sid = make_client_uni_sid_from_index(k);
        ensure_stream_for_path(c, st, &sid, k);
        st->sid_per_path[k] = sid;
    }

    /* 3. 경로 고정(Affinity) 재확인 */
    // if (picoquic_set_stream_path_affinity(c, sid, p->unique_path_id) != 0) {
    //     return -2; 
    // }

    // [수정 코드]
    // tx_t 구조체(st)에 마지막 사용 경로 인덱스(last_pi)가 이미 있으므로 이를 활용
    if (st->last_pi != k) { 
        if (picoquic_set_stream_path_affinity(c, sid, p->unique_path_id) != 0) {
            return -2; 
        }
        st->last_pi = k; // 경로가 변경되었을 때만 업데이트
    }

    /* 4. 데이터 추가 (헤더 + 페이로드 순차 전송) */
    int r1 = picoquic_add_to_stream_with_ctx(c, sid, hdr, hlen, 0, st);
    int r2 = (r1 == 0) ? picoquic_add_to_stream_with_ctx(c, sid, payload, plen, 0, st) : r1;
    
    return r2; 
}

/**
 * @brief 64비트 정수를 QUIC Variable Length Integer 포맷으로 인코딩합니다.
 */
static inline size_t varint_enc(uint64_t v, uint8_t* o){
    if(v < (1ull<<6))   { o[0] = (uint8_t)v; return 1; }
    
    if(v < (1ull<<14))  { o[0]=0x40|(v>>8); o[1]=v; return 2; }
    
    if(v < (1ull<<30))  { o[0]=0x80|(v>>24); o[1]=v>>16; o[2]=v>>8; o[3]=v; return 4; }
    
    o[0]=0xC0|(v>>56); o[1]=v>>48; o[2]=v>>40; o[3]=v>>32;
    o[4]=v>>24; o[5]=v>>16; o[6]=v>>8; o[7]=v; 
    
    return 8;
}

/**
 * @brief 특정 경로에 스트림을 바인딩하고 준비 상태로 설정합니다.
 */
static int ensure_bind(picoquic_cnx_t* c, tx_t* st, int i){
    if(!c || !st) return -1;
    if(!verified(c,i)) return -1;
    if(st->b[i].ready) return 0;

    /* 새 로컬 단방향 스트림 ID 확보 */
    uint64_t sid = picoquic_get_next_local_stream_id(c, /*unidir=*/1);
    picoquic_path_t* path = px_get_path(c, i);
    if(!path) return -1;

    /* 경로 선호도 고정 및 상태 저장 */
    picoquic_set_stream_path_affinity(c, sid, path->unique_path_id);
    st->b[i].sid = sid;
    st->b[i].ready = 1;
    
    LOGF("bind: path[%d] uid=%" PRIu64 " -> sid=%" PRIu64, i, path->unique_path_id, sid);
    return 0;
}

/**
 * @brief 인덱스를 기반으로 특정 스트림의 경로 선호도를 설정합니다.
 */
static inline int set_affinity_by_index(picoquic_cnx_t* c, uint64_t sid, int i){
    if (!c || i < 0 || i >= (int)c->nb_paths) return -1;
    
    picoquic_path_t* p = c->path[i];
    if (!p) return -1;
    
    return picoquic_set_stream_path_affinity(c, sid, p->unique_path_id);
}

/**
 * @brief 경로 활성화를 위해 더미 데이터를 전송하여 Warm-up을 수행합니다.
 */
static inline void warmup_path(picoquic_cnx_t* c, int sid, int bytes)
{
    static uint8_t warmbuf[8192];
    picoquic_add_to_stream_with_ctx(c, sid, warmbuf, bytes, 0, NULL);
}

/**
 * @brief 마지막으로 사용된 경로를 추적합니다. (현재 구현상 미사용 인자 제거용)
 */
static inline void use_path(picoquic_cnx_t* c, picoquic_path_t* p){
    (void)c; 
    static picoquic_path_t* last = NULL;
    if (p && p != last){
        last = p;
    }
}

/**
 * @brief 패킷 루프 콜백 모드의 이름을 문자열로 반환합니다.
 */
static inline const char* cbmode_str(picoquic_packet_loop_cb_enum m){
    switch(m){
        case picoquic_packet_loop_ready:         return "ready";
        case picoquic_packet_loop_after_receive: return "after_recv";
        case picoquic_packet_loop_after_send:    return "after_send";
        case picoquic_packet_loop_wake_up:       return "wake_up";
        default:                                  return "other";
    }
}

#endif