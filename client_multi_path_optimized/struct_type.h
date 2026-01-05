#ifndef STRUCT_TYPE_H
#define STRUCT_TYPE_H

#include "default_header.h"

/* * [bind_t]
 * 특정 경로(Path)와 스트림 ID(SID) 사이의 바인딩 상태를 관리합니다. 
 */
typedef struct { 
    uint64_t sid;    /* 스트림 ID */
    int ready;       /* 해당 스트림의 준비 완료 여부 */
} bind_t;

/* 최대 경로 수 정의 */
#ifndef MAX_PATHS
#define MAX_PATHS 16
#endif

/* * [tx_t]
 * 데이터 전송(TX)에 필요한 모든 상태 정보와 버퍼를 관리하는 핵심 구조체입니다. 
 */
typedef struct {
    /* 경로별 바인딩 정보 및 상태 저장 */
    bind_t b[MAX_PATHS];            

    /* picoquic 연결 객체 포인터 */
    picoquic_cnx_t* cnx;

    /* 상대방의 close 요청 확인 기록 (조기 종료 방지용) */
    int peer_close_seen;            

    /* Path A: 기본 서버 주소 정보 */
    struct sockaddr_storage peerA;
    int hasA;

    /* Path B: 보조 서버 주소 정보 (동일 서버 내 다른 IP 등) */
    struct sockaddr_storage peerB;
    int hasB;

    /* 보조 NIC (예: wlan0, eth1 등)의 로컬 소스 주소 */
    struct sockaddr_storage local_alt;
    int has_local_alt;

    /* USB NIC (예: usb0, 핫스팟 등)의 로컬 소스 주소 */
    struct sockaddr_storage local_usb;
    int has_local_usb;  

    /* 각 경로별 probing 및 실행 상태 플래그 */
    int didA, didB, didC;
    int is_ready, closing;

    /* 타임스탬프 및 시퀀스 관리 */
    uint64_t ready_ts_us;           /* 준비 완료 시간 (us) */
    uint64_t last_keepalive_us;     /* 마지막 keepalive 송신 시간 */
    uint64_t seq;                   /* 전송 시퀀스 번호 */

    /* 프레임 및 인터벌 제어 */
    size_t   frame_bytes;           /* 프레임 크기 */
    int      rr;                    /* 라운드 로빈 인덱스 */
    uint64_t send_interval_us;      /* 전송 간격 (us) */

    /* 카메라 캡처 버퍼 (실제 전송용/TX 전용) */
    camera_handle_t cam;            /* 카메라 핸들 */
    size_t   cap_cap;               /* 캡처 버퍼의 총 용량 */
    size_t   pending_off;           /* 데이터 송신 오프셋 (초기값 0) */
    int      last_pi;               /* 마지막 사용 경로 인덱스 (초기값 -1) */
    uint8_t* cap_buf;               /* 캡처된 데이터를 담는 실제 버퍼 */

    /* QUIC varint 인코딩을 위한 프레임 길이 저장용 버퍼 */
    uint8_t  lenb[8];

    /* 경로별 전용 스트림 ID 관리 (0이면 미개설 상태) */
    uint64_t sid_per_path[MAX_PATHS];
    
    /* 네트워크 바이트오더로 저장된 주 로컬 IP 주소 */
    uint32_t primary_local_ip; 

    /* * [카메라 전용 스레드/공유 리소스] 
     * 백그라운드 캡처 스레드와 메인 루프 간의 동기화를 위한 변수들입니다.
     */
    pthread_t       cam_thread;     /* 카메라 캡처 스레드 ID */
    pthread_mutex_t cam_mtx;        /* 공유 데이터 보호를 위한 뮤텍스 */
    int             cam_thread_started;
    int             cam_stop;       /* 1이면 캡처 스레드 종료 시퀀스 진행 */

    /* 캡처 스레드가 직접 데이터를 쓰는 버퍼와 상태 */
    uint8_t* cam_buf;              /* 실시간 캡처 데이터 버퍼 */
    size_t    cam_cap;              /* cam_buf의 총 용량 */
    int       cam_len;              /* 가장 최근에 캡처된 프레임의 실제 길이 */
    uint64_t  cam_seq;              /* 프레임별 고유 시퀀스 번호 */
    uint64_t  last_sent_seq;        /* 메인 루프에서 마지막으로 전송 성공한 seq */

    /* 알고리즘 및 모니터링용 메트릭 */
    uint64_t hs_done_ts;            /* 핸드셰이크가 완료된 타임스탬프 */
    int last_primary_idx;           /* 직전에 선택되었던 Primary 경로 인덱스 */
    uint64_t last_switch_ts;        /* 마지막으로 경로 전환이 일어난 타임스탬프 */
    uint32_t ip_wlan_be;            /* Wi-Fi 인터페이스 IP (Big Endian) */
    uint32_t ip_usb_be;             /* USB 인터페이스 IP (Big Endian) */
    int last_verified;              /* 마지막 경로 검증 상태 */

} tx_t;

/* * [pathsel_t]
 * 사용 가능한 경로 리스트를 구축할 때 사용하는 구조체입니다. 
 */
typedef struct {
    int idx;                        /* 경로 인덱스 */
    int sid;                        /* 할당된 스트림 ID */
    picoquic_path_t* p;             /* picoquic 내부 경로 객체 포인터 */
    uint32_t ip_be;                 /* 로컬 IP 주소 (Big Endian) */
    uint64_t rtt;                   /* RTT 정보 */
    uint64_t loss;                  /* 손실 정보 */
    uint64_t delivered;             /* 전달 완료된 데이터량 */
} pathsel_t;

/* * [path_metric_t]
 * 경로의 품질을 평가하기 위한 세부 메트릭 정보를 담고 있습니다. 
 */
typedef struct {
    int grade;              /* 품질 등급 (0=GOOD, 1=WARN, 2=BAD) */
    uint64_t rtt;           /* smoothed RTT 값 */
    double loss_rate;       /* 패킷 손실률 (%) */
    double goodput;         /* 유효 대역폭 (Mbps) */
    uint64_t score;         /* 알고리즘 점수 */
    double rtt_ms;          /* 밀리초 단위 RTT */
    double rtt_var_ms;      /* RTT 변동폭 (Jitter) */
} path_metric_t;

#endif