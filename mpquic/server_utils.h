#ifndef SERVER_UTILS_H
#define SERVER_UTILS_H

#include "init.h"

/* ============================================================
 * [1] 기본 구성 및 상수 설정
 * ============================================================ */

#define DEFAULT_CERT "cert.pem"        /* 서버 인증서 경로 */
#define DEFAULT_KEY  "key.pem"         /* 서버 비밀키 경로 */
#define DEFAULT_PORT 4433              /* 기본 리스닝 포트 */
#define ONE_SEC_US   1000000ULL        /* 1초(us) */
#define MAX_FRAME    (8 * 1024 * 1024) /* 단일 프레임 최대 제한 (8MB) */
#define MAX_PRINTED  128               /* 로그 출력 관리용 커넥션 최대 수 */

/**
 * @brief 연결(Connection)별 로그 출력 상태를 관리하는 구조체입니다.
 */
typedef struct { 
    picoquic_cnx_t* cnx; 
    int printed; 
} printed_t;


/* ============================================================
 * [2] 전역 설정 변수 (기본값)
 * ============================================================ */

static char      g_outdir[256] = "frames_out";  /* 프레임 저장 디렉토리 */
static int       g_max_frames  = 0;             /* 최대 수신 프레임 수 (0:무제한) */
static uint64_t  g_saved_frames = 0;            /* 현재까지 저장된 총 프레임 수 */
static uint64_t  g_last_rx_log_us = 0;          /* 마지막 수신 로그 기록 시간 */
static printed_t g_printed[MAX_PRINTED];        /* 출력된 커넥션 목록 */


/* ============================================================
 * [3] 로깅 및 디버그 유틸리티
 * ============================================================ */

#ifndef LOGF
/**
 * @brief 로그 출력 시 현재 시간(밀리초 포함)을 접두어로 출력합니다.
 */
static inline void logf_ts_prefix(FILE* fp){
    struct timespec ts; 
    clock_gettime(CLOCK_REALTIME, &ts);
    
    struct tm tm; 
    localtime_r(&ts.tv_sec, &tm);
    
    char buf[32];
    strftime(buf, sizeof(buf), "%m-%d %H:%M:%S", &tm);
    
    /* [월-일 시:분:초.밀리초] 형식 */
    fprintf(fp, "[%s.%03ld] ", buf, ts.tv_nsec / 1000000L);
}

/**
 * @brief 타임스탬프를 포함하여 가변 인자 형식의 로그를 출력합니다.
 */
static inline void LOGF(const char* fmt, ...){
    va_list ap; 
    va_start(ap, fmt);
    
    logf_ts_prefix(stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    
    va_end(ap);
}
#endif


/* ============================================================
 * [4] 네트워크 및 시스템 유틸리티
 * ============================================================ */

/**
 * @brief picoquic의 연결 상태(Enum)를 읽기 쉬운 문자열로 변환합니다.
 */
static inline const char* cnx_state_str(picoquic_state_enum s){
    switch(s){
        case picoquic_state_client_init:            return "client_init";
        case picoquic_state_client_init_sent:       return "client_init_sent";
        case picoquic_state_server_init:            return "server_init";
        case picoquic_state_server_handshake:       return "server_hs";
        case picoquic_state_client_handshake_start: return "cli_hs_start";
        case picoquic_state_handshake_failure:      return "hs_fail";
        case picoquic_state_ready:                  return "ready";
        case picoquic_state_disconnecting:          return "disconnecting";
        case picoquic_state_draining:               return "draining";
        case picoquic_state_disconnected:           return "disconnected";
        default:                                    return "other";
    }
}

/**
 * @brief sockaddr 구조체 주소를 "IP:Port" 형태의 문자열로 변환합니다.
 */
static inline void addr_to_str(const struct sockaddr* sa, char* out, size_t cap){
    if (!sa || !out || cap == 0){ return; }
    
    char host[NI_MAXHOST] = {0}, serv[NI_MAXSERV] = {0};
    socklen_t slen = (sa->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    
    if (getnameinfo(sa, slen, host, sizeof(host), serv, sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV) == 0){
        if (sa->sa_family == AF_INET6) 
            snprintf(out, cap, "[%s]:%s", host, serv);
        else 
            snprintf(out, cap, "%s:%s", host, serv);
    } else {
        snprintf(out, cap, "(unknown)");
    }
}

/**
 * @brief 디렉토리가 존재하는지 확인하고 없으면 생성합니다.
 */
static inline void ensure_dir(const char* path){
    if (!path || !*path) return;
    
    /* 0777 권한으로 디렉토리 생성 (이미 존재하면 조용히 실패함) */
    mkdir(path, 0777); 
}

/**
 * @brief 특정 디렉토리에 쓰기 권한이 있는지 임시 파일을 통해 확인합니다.
 */
static inline int dir_writable(const char* d){
    if (!d || !*d) return 0;
    
    ensure_dir(d);
    
    char testp[512]; 
    snprintf(testp, sizeof(testp), "%s/.probe", d);
    
    FILE* f = fopen(testp, "wb");
    if (!f) return 0;
    
    fputs("ok", f);
    fclose(f);
    remove(testp);
    
    return 1;
}


/* ============================================================
 * [5] 연결 로그 출력 관리
 * ============================================================ */

/**
 * @brief 해당 커넥션에 대한 READY 로그가 이미 출력되었는지 확인합니다.
 */
static inline int cnx_marked_printed(picoquic_cnx_t* c){
    for (int i = 0; i < MAX_PRINTED; i++){
        if (g_printed[i].printed && g_printed[i].cnx == c) return 1;
    }
    return 0;
}

/**
 * @brief 해당 커넥션을 로그 출력 완료 목록에 기록합니다.
 */
static inline void cnx_mark_set(picoquic_cnx_t* c){
    for (int i = 0; i < MAX_PRINTED; i++){
        if (!g_printed[i].printed){
            g_printed[i].printed = 1;
            g_printed[i].cnx = c;
            return;
        }
    }
}

/**
 * @brief 수신된 바이트의 앞부분을 16진수로 덤프(Hexdump) 출력합니다. (디버깅용)
 */
static inline void dump_prefix(const uint8_t* p, size_t len, size_t n) {
    size_t m = (len < n) ? len : n;
    
    fprintf(stderr, "[SVR][dump] ");
    for (size_t i = 0; i < m; i++) 
        fprintf(stderr, "%02x", p[i]);
    
    if (len > n) 
        fprintf(stderr, "...(+%zu)", len - n);
        
    fprintf(stderr, "\n");
}

#endif /* SERVER_UTILS_H */