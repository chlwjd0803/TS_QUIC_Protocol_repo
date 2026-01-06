#ifndef NET_TOOLS_H
#define NET_TOOLS_H

#include "default_header.h"
#include "struct_type.h"

/* net_tools.h 최상단에 추가 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE  /* SO_BINDTODEVICE 같은 GNU 확장 기능을 활성화합니다. */
#endif

#include <net/if.h>  /* 인터페이스 관련 정의를 위해 필요할 수 있습니다. */
#include <sys/socket.h>
#include <string.h>

/* 만약 위 헤더를 추가해도 빨간 줄이 안 사라진다면, 아래와 같이 직접 상수를 정의해버려도 됩니다. */
#ifndef SO_BINDTODEVICE
#define SO_BINDTODEVICE 25
#endif

/* ============================================================
 * [1] 파일 시스템 및 공통 상수 설정
 * ============================================================ */

/**
 * @brief 필요한 디렉토리가 없을 경우 생성합니다.
 */
static void ensure_dir(const char* path){
    if (!path || !*path) return;
    
    /* 0777 권한으로 디렉토리 생성 (이미 존재하면 실패하지만 무시함) */
    mkdir(path, 0777); 
}

#define MTU_CHUNK    (16 * 1024)   /* 16KB 단위 데이터 처리 */
#define ONE_SEC_US   1000000ULL    /* 1초를 마이크로초(us)로 정의 */

/**
 * @brief 표준 에러 출력으로 로그를 남기기 위한 매크로입니다.
 */
#define LOGF(fmt, ...)  fprintf(stderr, "[CLI] " fmt "\n", ##__VA_ARGS__)


/* ============================================================
 * [2] 네트워크 주소 해석 및 저장
 * ============================================================ */

/**
 * @brief 도메인 이름 또는 IP 문자열을 sockaddr_storage 구조체로 변환합니다.
 * @param host 서버 호스트 이름 또는 IP 주소
 * @param port 포트 번호
 * @param out 결과가 저장될 구조체 포인터
 */
static int resolve_ip(const char* host, int port, struct sockaddr_storage* out){
    if (!host || !out) return -1;

    char port_s[16]; 
    snprintf(port_s, sizeof(port_s), "%d", port);

    struct addrinfo hints, *ai = NULL;
    memset(&hints, 0, sizeof(hints));

    /* UDP 전송을 위한 힌트 설정 */
    hints.ai_family = AF_UNSPEC; 
    hints.ai_socktype = SOCK_DGRAM;

    int r = getaddrinfo(host, port_s, &hints, &ai);
    
    if (r != 0 || !ai) return -1;

    /* 해석된 첫 번째 주소 정보를 복사 */
    memcpy(out, ai->ai_addr, ai->ai_addrlen);
    
    freeaddrinfo(ai);
    return 0;
}

/**
 * @brief IP 문자열(v4/v6)을 해석하여 sockaddr_storage 구조체에 명시적으로 저장합니다.
 */
static int store_local_ip(const char* ip, uint16_t port, struct sockaddr_storage* out) {
    if (!ip || !out) return -1;
    
    memset(out, 0, sizeof(*out));

    /* IPv4 해석 시도 */
    struct in_addr v4;
    if (inet_pton(AF_INET, ip, &v4) == 1) {
        struct sockaddr_in* sa = (struct sockaddr_in*)out;
        sa->sin_family = AF_INET;
        sa->sin_port = htons(port);
        sa->sin_addr = v4;
        return 0;
    }

    /* IPv6 해석 시도 */
    struct in6_addr v6;
    if (inet_pton(AF_INET6, ip, &v6) == 1) {
        struct sockaddr_in6* sa6 = (struct sockaddr_in6*)out;
        sa6->sin6_family = AF_INET6;
        sa6->sin6_port = htons(port);
        sa6->sin6_addr = v6;
        return 0;
    }

    return -1; // 유효한 IP 주소 형식이 아님
}


/* ============================================================
 * [3] 소켓 생성 및 바인딩
 * ============================================================ */

/**
 * @brief 특정 로컬 IP와 포트에 바인딩하고, 물리적 NIC까지 강제로 지정합니다.
 */
int make_bound_socket(const char* ip, int port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    /* 1. 하드웨어 이름 지정 (사용자 시스템 확인 값) */
    const char* if_wlan = "wlP1p1s0"; 
    const char* if_cellular  = "enx2a022e8f65a1";

    /* 2. 목적지 IP 대역에 따른 물리적 NIC 강제 고정 */
    if (ip != NULL) {
        if (strncmp(ip, "192.168", 7) == 0) {
            setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, if_wlan, strlen(if_wlan));
        } else if (strncmp(ip, "172.20", 6) == 0) { // 핫스팟 대역 체크
            setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, if_cellular, strlen(if_cellular));
    }
}

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }

    LOGF("[SOCK] bound %s:%d fd=%d (Hardware-Locked)", ip, port, fd);
    return fd;
}


/* ============================================================
 * [4] 주소 비교 및 디버그 유틸리티
 * ============================================================ */

/* 테스트 중 사용하지 않을 IP 차단용 상수 (가드) */
static const char* FORBID_LOCAL_IP = "192.168.0.5";

/**
 * @brief IP 문자열을 sockaddr_in 구조체로 변환합니다.
 */
static int str_to_sockaddr4(const char* ip, struct sockaddr_in* out){
    memset(out, 0, sizeof(*out));
    out->sin_family = AF_INET;
    
    return inet_pton(AF_INET, ip, &out->sin_addr) == 1 ? 0 : -1;
}

/**
 * @brief sockaddr 정보를 사람이 읽을 수 있는 문자열 형식으로 출력합니다. (디버깅용)
 */
__attribute__((unused))
static void print_sockaddr(const char* tag, const struct sockaddr* sa){
    char buf[128] = {0};
    uint16_t port = 0;

    if (sa->sa_family == AF_INET) {
        /* IPv4 출력 처리 */
        const struct sockaddr_in* v4 = (const struct sockaddr_in*)sa;
        inet_ntop(AF_INET, &v4->sin_addr, buf, sizeof(buf));
        port = ntohs(v4->sin_port);
    } 
    else if (sa->sa_family == AF_INET6) {
        /* IPv6 출력 처리 */
        const struct sockaddr_in6* v6 = (const struct sockaddr_in6*)sa;
        inet_ntop(AF_INET6, &v6->sin6_addr, buf, sizeof(buf));
        port = ntohs(v6->sin6_port);
    } 
    else {
        snprintf(buf, sizeof(buf), "fam=%d", sa->sa_family);
    }

    LOGF("%s: %s:%u", tag, buf, port);
}

/**
 * @brief 두 sockaddr 구조체가 동일한 IP와 포트를 가졌는지 비교합니다.
 */
__attribute__((unused))
static int sockaddr_equal(const struct sockaddr* a, const struct sockaddr* b){
    if (a->sa_family != b->sa_family) return 0;

    if (a->sa_family == AF_INET) {
        const struct sockaddr_in* x = (const struct sockaddr_in*)a;
        const struct sockaddr_in* y = (const struct sockaddr_in*)b;
        
        return (x->sin_addr.s_addr == y->sin_addr.s_addr && 
                x->sin_port == y->sin_port);
    }

    if (a->sa_family == AF_INET6) {
        const struct sockaddr_in6* x = (const struct sockaddr_in6*)a;
        const struct sockaddr_in6* y = (const struct sockaddr_in6*)b;
        
        return (memcmp(&x->sin6_addr, &y->sin6_addr, sizeof(x->sin6_addr)) == 0) &&
               (x->sin6_port == y->sin6_port);
    }

    return 0;
}

/**
 * @brief 특정 경로(Path)의 로컬 IP가 지정된 IP 문자열과 일치하는지 확인합니다.
 */
static int path_is_local_ip(const picoquic_path_t* p, const char* ip4){
    if (!p || !p->first_tuple || !ip4) return 0;

    struct sockaddr_in ban;
    if (str_to_sockaddr4(ip4, &ban) != 0) return 0;

    /* picoquic 경로 내부의 로컬 주소 가져오기 */
    const struct sockaddr* la = (const struct sockaddr*)&p->first_tuple->local_addr;

    if (!la || la->sa_family != AF_INET) return 0;

    /* IPv4 주소 비교 */
    const struct sockaddr_in* la4 = (const struct sockaddr_in*)la;
    
    return (la4->sin_addr.s_addr == ban.sin_addr.s_addr);
}

#endif