#ifndef SERVER_LEGACY_H
#define SERVER_LEGACY_H

#include "init.h"
#include "server_utils.h"
#include "server_worker.h"

/* ============================================================
 * [1] 스트림별 수신 상태 및 세션 테이블 구조
 * ============================================================ */

/**
 * @brief 개별 스트림의 수신 상태를 추적하는 컨텍스트입니다.
 */
typedef struct {
    uint8_t  hbuf[8];  /* VarInt 길이 헤더를 임시로 담는 버퍼 */
    size_t   hgot;     /* 현재까지 수신된 헤더 바이트 수 */
    int      hdone;    /* 헤더 파싱 완료 여부 플래그 */
    uint64_t plen;     /* 파싱된 페이로드(프레임) 전체 길이 */
    uint64_t pgot;     /* 현재까지 수신된 페이로드 바이트 수 */
    uint8_t* payload;  /* 프레임 데이터가 조립되는 버퍼 */
    size_t   cap;      /* payload 버퍼의 현재 용량 */
    uint64_t frames;   /* 이 스트림을 통해 전달된 총 프레임 수 */
} rx_stream_ctx_t;

/**
 * @brief 스트림 ID(sid)와 수신 컨텍스트를 매핑하는 슬롯 구조체입니다.
 */
typedef struct {
    int used;
    uint64_t sid;
    rx_stream_ctx_t* ctx;
} sid_slot_t;

/**
 * @brief 전체 세션의 스트림 관리 테이블입니다.
 */
typedef struct {
    sid_slot_t slot[MAX_STREAMS];
} rx_session_t;


/* ============================================================
 * [2] 파일 저장 및 작업 큐 처리 (Legacy 방식)
 * ============================================================ */

/**
 * @brief 수신된 바이트 데이터를 개별 JPG 파일로 저장합니다.
 */
static inline int save_bytes_as_file(const char* dir, uint64_t idx,
                              const uint8_t* data, size_t len)
{
    if (!dir || !*dir || !data || len == 0) return -1;

    /* 디렉토리 존재 확인 및 생성 */
    ensure_dir(dir);

    char path[512];
    snprintf(path, sizeof(path), "%s/frame_%06" PRIu64 ".jpg", dir, idx);

    FILE* f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "[SVR] fopen fail: %s\n", path);
        return -1;
    }

    size_t w = fwrite(data, 1, len, f);
    fclose(f);

    if (w != len) {
        fprintf(stderr, "[SVR] partial write: %s (%zu/%zu)\n", path, w, len);
        return -1;
    }
    return 0;
}

/**
 * @brief 수신된 작업을 처리합니다. (현재 구현은 별도 큐 없이 즉시 파일 저장)
 */
static inline int jobq_push(job_t j) {
    int rc = save_bytes_as_file(g_outdir, j.app->frame_idx++, j.buf, j.len);
    
    /* 처리가 끝나면 할당된 버퍼 해제 */
    free(j.buf);
    return rc;
}


/* ============================================================
 * [3] 세션 및 컨텍스트 관리 헬퍼
 * ============================================================ */

/**
 * @brief 스트림 컨텍스트 자원을 해제합니다.
 */
static inline void rx_ctx_free(rx_stream_ctx_t* s){
    if(!s) return;
    if(s->payload) free(s->payload);
    free(s);
}

/**
 * @brief 새로운 스트림 컨텍스트를 생성합니다.
 */
static inline rx_stream_ctx_t* rx_ctx_new(void){
    rx_stream_ctx_t* s = (rx_stream_ctx_t*)calloc(1, sizeof(rx_stream_ctx_t));
    return s;
}

/**
 * @brief 세션 테이블에서 특정 sid를 찾거나 없으면 새로 생성하여 반환합니다.
 */
static inline rx_stream_ctx_t* session_get_or_make(rx_session_t* ss, uint64_t sid){
    if (!ss) return NULL;

    /* 1. 기존에 등록된 sid가 있는지 확인 */
    for (int i=0; i<MAX_STREAMS; i++){
        if (ss->slot[i].used && ss->slot[i].sid == sid) return ss->slot[i].ctx;
    }

    /* 2. 비어있는 슬롯을 찾아 새로 등록 */
    for (int i=0; i<MAX_STREAMS; i++){
        if (!ss->slot[i].used){
            ss->slot[i].used = 1;
            ss->slot[i].sid  = sid;
            ss->slot[i].ctx  = rx_ctx_new();
            return ss->slot[i].ctx;
        }
    }
    return NULL;
}

/**
 * @brief 스트림 종료 시 해당 세션 슬롯을 정리합니다.
 */
static inline void session_close_sid(rx_session_t* ss, uint64_t sid){
    if (!ss) return;
    for (int i=0; i<MAX_STREAMS; i++){
        if (ss->slot[i].used && ss->slot[i].sid == sid){
            rx_ctx_free(ss->slot[i].ctx);
            memset(&ss->slot[i], 0, sizeof(ss->slot[i]));
            return;
        }
    }
}


/* ============================================================
 * [4] QUIC VarInt 디코딩 및 프레임 조립 로직
 * ============================================================ */

/**
 * @brief 가변 길이 정수(VarInt)를 디코딩하여 프레임 길이를 추출합니다.
 */
static inline int varint_decode(const uint8_t* b, size_t blen, uint64_t* val, size_t* used){
    if (blen == 0) return 0;
    
    uint8_t fb = b[0];
    if ((fb & 0xC0) == 0x00){ /* 1 byte 인코딩 */
        *val = (uint64_t)(fb & 0x3F);
        *used = 1;
        return 1;
    } else if ((fb & 0xC0) == 0x40){ /* 2 bytes 인코딩 */
        if (blen < 2) return 0;
        *val = ((uint64_t)(fb & 0x3F) << 8) | b[1];
        *used = 2;
        return 1;
    } else if ((fb & 0xC0) == 0x80){ /* 4 bytes 인코딩 */
        if (blen < 4) return 0;
        *val = ((uint64_t)(fb & 0x3F) << 24) | ((uint64_t)b[1] << 16) | ((uint64_t)b[2] << 8) | b[3];
        *used = 4;
        return 1;
    } else { /* 8 bytes 인코딩 */
        if (blen < 8) return 0;
        *val = ((uint64_t)(fb & 0x3F) << 56) |
               ((uint64_t)b[1] << 48) | ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32) |
               ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) | ((uint64_t)b[6] << 8) | b[7];
        *used = 8;
        return 1;
    }
}

/**
 * @brief 완성된 프레임을 복사하여 워커 큐(rxq)로 전달합니다.
 */
static inline void on_frame_copy(rx_stream_ctx_t* s, app_ctx_t* app){
    if (!s || !s->payload || s->plen == 0 || !app) return;
    
    uint8_t* cp = (uint8_t*)malloc(s->plen);
    if (!cp) return;
    
    memcpy(cp, s->payload, s->plen);
    
    rx_item_t it = { .buf=cp, .len=(size_t)s->plen, .seq_hint=0, .ts_hint=0.0 };
    rxq_push(&g_rxq, it);
    
    app->frame_count++;
    app->bytes_saved_total += s->plen;
}

/**
 * @brief 수신 바이트 열을 스트림 컨텍스트에 입력하여 프레임을 조립합니다. (핵심 FSM)
 */
static inline int feed_bytes(rx_stream_ctx_t* s, app_ctx_t* app,
                      const uint8_t* buf, size_t len)
{
    size_t off = 0;

    while (off < len) {
        if (!s->hdone) {
            /* [단계 1] 헤더 누적: VarInt 길이를 파싱하기 위해 8바이트까지 모음 */
            size_t room = sizeof(s->hbuf) - s->hgot;
            size_t to = (len - off < room) ? (len - off) : room;
            
            memcpy(s->hbuf + s->hgot, buf + off, to);
            s->hgot += to;
            off     += to;

            /* [단계 2] VarInt 파싱 시도 */
            uint64_t plen = 0;
            size_t   used = 0;
            int ok = varint_decode(s->hbuf, s->hgot, &plen, &used);

            if (ok < 0) {
                /* 파싱 에러 발생 시 상태 리셋 */
                s->hgot = 0; s->hdone = 0; s->plen = s->pgot = 0;
                continue;
            }
            if (!ok) continue; /* 바이트가 더 필요함 */

            /* [단계 3] 프레임 길이 결정 */
            if (plen == 0 || plen > MAX_FRAME) {
                s->hgot = 0; s->hdone = 0; s->plen = s->pgot = 0;
                continue;
            }
            
            s->hdone = 1;
            s->plen  = (size_t)plen;
            s->pgot  = 0;

            /* [단계 4] 헤더 버퍼 뒤에 남은 잔여 데이터 처리 */
            size_t remain = s->hgot - used;
            const uint8_t* p_payload0 = (remain ? (s->hbuf + used) : NULL);

            /* 조립 버퍼 용량 확보 */
            if (ensure_cap(&s->payload, &s->cap, s->plen, MAX_FRAME) != 0) {
                s->hgot = 0; s->hdone = 0; s->plen = s->pgot = 0;
                continue;
            }

            if (remain) {
                size_t first = (remain < s->plen) ? remain : s->plen;
                memcpy(s->payload, p_payload0, first);
                s->pgot = first;
            }

            s->hgot = 0;

            /* 잔여 데이터만으로 프레임이 완성된 경우 즉시 처리 */
            if (s->pgot == s->plen) {
                on_frame_copy(s, app);
                s->hdone = 0; s->plen = 0; s->pgot = 0;
                continue;
            }
        } 
        else {
            /* [단계 5] 페이로드 수집: 파싱된 길이만큼 데이터 누적 */
            size_t   avail  = len - off;
            uint64_t left64 = (s->plen > s->pgot) ? (s->plen - s->pgot) : 0;
            
            if (left64 == 0) {
                s->hdone = 0; s->plen = 0; s->pgot = 0;
                continue;
            }
            
            size_t left = (left64 > SIZE_MAX) ? SIZE_MAX : (size_t)left64;
            size_t to = (avail < left) ? avail : left;
            
            if (to == 0) break;

            /* 버퍼 용량 재확인 및 확장 */
            if (ensure_cap(&s->payload, &s->cap, s->pgot + to, MAX_FRAME) != 0) {
                s->hdone = 0; s->plen = 0; s->pgot = 0;
                continue;
            }

            memcpy(s->payload + s->pgot, buf + off, to);
            s->pgot += to;
            off     += to;

            /* 프레임 조립 완료 체크 */
            if (s->pgot == s->plen) {
                on_frame_copy(s, app);
                s->hdone = 0; s->plen = 0; s->pgot = 0;
            }
        }
    }
    return 0;
}

#endif