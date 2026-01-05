#ifndef APP_CTX_SERVER_H
#define APP_CTX_SERVER_H

#include <stddef.h>

/* ============================================================
 * [1] 시스템 제한 및 설정 상수
 * ============================================================ */

#ifndef OUT_DIR_MAX
#define OUT_DIR_MAX 512
#endif

#ifndef MAX_STREAMS
#define MAX_STREAMS 16  /* 동시에 처리할 최대 스트림(경로) 수 */
#endif

#ifndef MAX_FRAME_SIZE
#define MAX_FRAME_SIZE ((size_t)(10ULL * 1024ULL * 1024ULL)) /* 최대 프레임 크기 (10MB) */
#endif

#ifndef AUTHORITY_MAX
#define AUTHORITY_MAX 128
#endif

#ifndef PATH_MAX_WT
#define PATH_MAX_WT 256
#endif

#ifndef MAX_APP_PATHS
#define MAX_APP_PATHS 16
#endif


/* ============================================================
 * [2] 데이터 수신 상태 머신 (State Machine) 정의
 * ============================================================ */

/**
 * @brief 스트림으로부터 바이트를 읽을 때 현재 어떤 부분을 기다리는지 나타냅니다.
 */
typedef enum {
    RX_WANT_LEN = 0,      /* 프레임 길이(VarInt) 정보를 기다리는 상태 */
    RX_WANT_PAYLOAD = 1,  /* 실제 프레임 데이터(Payload)를 기다리는 상태 */
    RX_RESYNC_JPEG = 2,   /* 데이터 오류 시 JPEG 헤더(FF D8)를 찾아 동기화하는 상태 */
} rx_state_e;


/* ============================================================
 * [3] 스트림 및 애플리케이션 컨텍스트 구조체
 * ============================================================ */

/**
 * @brief 개별 스트림(sid)별 수신 상태를 관리하는 구조체입니다.
 */
typedef struct rx_stream_s {
    int      in_use;         /* 현재 이 슬롯이 사용 중인지 여부 */
    uint64_t sid;            /* QUIC 스트림 ID */
    rx_state_e st;           /* 현재 수신 상태 (길이 대기 / 데이터 대기 등) */
    
    /* 길이 파싱용 버퍼 */
    uint8_t  len_buf[8];     /* 수신 중인 VarInt 바이트 저장 */
    size_t   len_got;        /* len_buf에 채워진 바이트 수 */
    
    /* 프레임 조립 정보 */
    uint64_t frame_size;     /* 파싱된 현재 프레임의 전체 크기 */
    uint64_t received;       /* 현재까지 수신 완료된 데이터 크기 */
    uint8_t* buf;            /* 데이터가 저장되는 실제 버퍼 포인터 */
    size_t   cap;            /* 현재 할당된 버퍼의 총 용량 */
    
    /* 통계 및 동기화 정보 */
    int      frame_no;       /* 스트림 내 프레임 순번 */
    int      in_jpeg;        /* JPEG 데이터 구간 진입 여부 */
    uint8_t  last_b;         /* 직전 바이트 (JPEG 마커 FF D8/D9 확인용) */
    uint64_t seq;            /* 시퀀스 번호 */
    
    /* 헤더 누적용 여유 버퍼 */
    uint8_t   hdr_buf[16];   
    size_t    hdr_len;       
} rx_stream_t;

/**
 * @brief 서버 애플리케이션의 전체 상태를 관리하는 최상위 구조체입니다.
 */
typedef struct {
    /* 파일 저장 및 출력 설정 */
    char     out_dir[256];   /* 프레임이 저장될 디렉토리 경로 */
    int      frame_count;    /* 현재까지 수신 완료된 총 프레임 수 */
    int      max_frames;     /* 수신할 최대 프레임 제한 (0이면 무제한) */
    
    /* 스트림별 상태 배열 */
    rx_stream_t rx[MAX_STREAMS];   

    /* 통계 및 모니터링 필드 */
    uint64_t   bytes_rx_total;     /* 네트워크로 수신한 총 바이트 수 */
    uint64_t   backlog_bytes;      /* 디스크 저장을 대기 중인 추정 데이터량 */
    uint64_t   frame_idx;          /* 저장 시 사용할 프레임 인덱스 */
    uint64_t   bytes_saved_total;  /* 실제로 디스크에 기록 완료된 총 바이트 수 */
} app_ctx_t;

#endif /* APP_CTX_SERVER_H */