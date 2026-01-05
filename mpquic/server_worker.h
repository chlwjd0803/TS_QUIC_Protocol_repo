#ifndef SERVER_WORKER_H
#define SERVER_WORKER_H

#include <sys/uio.h>
#include <fcntl.h>
#include "init.h"
#include "server_utils.h"

/* ============================================================
 * [1] 수신 큐(RX Queue) 데이터 구조
 * ============================================================ */

/**
 * @brief 큐에 담길 개별 프레임 아이템입니다.
 */
typedef struct {
    uint8_t* buf;       /* 프레임 데이터 버퍼 (동적 할당됨) */
    size_t   len;       /* 데이터 길이 */
    uint64_t seq_hint;  /* 인덱싱을 위한 시퀀스 힌트 (선택 사항) */
    double   ts_hint;   /* 타임스탬프 힌트 (선택 사항) */
} rx_item_t;

/* 수신 큐의 최대 용량 (라즈베리 파이 등 임베디드 환경 고려) */
#define RXQ_CAP  512   

/**
 * @brief 프레임 저장을 위한 스레드 안전한 순환 큐 구조체입니다.
 */
typedef struct {
    rx_item_t q[RXQ_CAP];  /* 아이템 배열 */
    int head, tail;        /* 머리와 꼬리 인덱스 */
    int closed;            /* 큐 종료 여부 플래그 */
    pthread_mutex_t m;     /* 동기화를 위한 뮤텍스 */
    pthread_cond_t  cv;    /* 블로킹 대기를 위한 조건 변수 */
} rx_queue_t;


/* ============================================================
 * [2] 세그먼트 라이터(Segment Writer) 구조
 * ============================================================ */

/**
 * @brief 데이터를 하나의 거대한 세그먼트 파일로 이어서 쓰는 라이터입니다.
 */
typedef struct {
    int fd;                /* 현재 오픈된 파일 디스크립터 */
    size_t bytes_in_seg;   /* 현재 세그먼트 파일에 기록된 총 바이트 */
    char dir[256];         /* 저장 디렉토리 경로 */
} seg_writer_t;

/* 전역 수신 큐 초기화 */
static rx_queue_t g_rxq = { 
    .head = 0, .tail = 0, .closed = 0,
    .m = PTHREAD_MUTEX_INITIALIZER, 
    .cv = PTHREAD_COND_INITIALIZER 
};


/* ============================================================
 * [3] 수신 큐 조작 함수 (Inline)
 * ============================================================ */

/**
 * @brief 큐에 아이템을 추가합니다 (뮤텍스 락 제외 내부 버전).
 * 큐가 가득 찼을 경우, 가장 오래된 데이터를 버리고(Drop) 새 데이터를 넣습니다.
 */
static inline int rxq_push_nolock(rx_queue_t* rq, rx_item_t it) {
    int next = (rq->head + 1) % RXQ_CAP;
    
    if (next == rq->tail) {
        /* 가득 참: 오래된 프레임을 해제하고 포인터 이동 (영상은 정지보다 드랍이 나음) */
        if (rq->q[rq->tail].buf) {
            free(rq->q[rq->tail].buf);
        }
        rq->tail = (rq->tail + 1) % RXQ_CAP;
    }
    
    rq->q[rq->head] = it;
    rq->head = next;
    return 0;
}

/**
 * @brief 큐에 아이템을 안전하게 추가하고 대기 중인 스레드에 신호를 보냅니다.
 */
static inline int rxq_push(rx_queue_t* rq, rx_item_t it) {
    pthread_mutex_lock(&rq->m);
    
    int r = rxq_push_nolock(rq, it);
    
    pthread_cond_signal(&rq->cv); /* 소비자 스레드 깨우기 */
    pthread_mutex_unlock(&rq->m);
    
    return r;
}

/**
 * @brief 큐에서 아이템을 하나 꺼내옵니다. 데이터가 없으면 있을 때까지 대기합니다.
 */
static inline int rxq_pop(rx_queue_t* rq, rx_item_t* out) {
    pthread_mutex_lock(&rq->m);
    
    /* 데이터가 없고 큐가 닫히지 않았으면 대기 */
    while (rq->head == rq->tail && !rq->closed) {
        pthread_cond_wait(&rq->cv, &rq->m);
    }
    
    /* 큐가 닫혔고 데이터도 없으면 종료 */
    if (rq->head == rq->tail && rq->closed) { 
        pthread_mutex_unlock(&rq->m); 
        return -1; 
    }
    
    *out = rq->q[rq->tail];
    rq->tail = (rq->tail + 1) % RXQ_CAP;
    
    pthread_mutex_unlock(&rq->m);
    return 0;
}

/**
 * @brief 수신 큐를 닫고 대기 중인 모든 스레드를 깨웁니다.
 */
static inline void rxq_close(rx_queue_t* rq){
    pthread_mutex_lock(&rq->m);
    rq->closed = 1;
    pthread_cond_broadcast(&rq->cv);
    pthread_mutex_unlock(&rq->m);
}


/* ============================================================
 * [4] 메모리 관리 및 파일 I/O 유틸리티
 * ============================================================ */

/**
 * @brief 버퍼 용량을 확인하고 필요 시 지수적으로 확장합니다.
 */
static inline int ensure_cap(uint8_t** buf, size_t* cap, size_t need, size_t max_cap){
    if (*cap >= need) return 0;
    
    size_t grow = (*cap ? *cap : 4096);
    while (grow < need) {
        if (grow >= max_cap / 2) { grow = need; break; } 
        grow <<= 1;
    }
    
    if (grow > max_cap) return -1;
    
    uint8_t* np = (uint8_t*)realloc(*buf, grow);
    if (!np) return -1;
    
    *buf = np; 
    *cap = grow;
    return 0;
}

/**
 * @brief 새로운 세그먼트 파일을 생성하고 오픈합니다 (파일명: 날짜-시간 기반).
 */
static inline int seg_open_new(seg_writer_t* w){
    time_t t = time(NULL);
    struct tm tm; 
    localtime_r(&t, &tm);
    
    char stamp[32];
    strftime(stamp, sizeof(stamp), "%Y%m%d-%H%M%S", &tm);
    
    char path[512];
    snprintf(path, sizeof(path), "%s/frames_%s.seg", w->dir, stamp);
    
    /* 파일 생성, 쓰기 전용, 이어쓰기 모드로 오픈 */
    w->fd = open(path, O_CREAT | O_WRONLY | O_APPEND, 0644);
    w->bytes_in_seg = 0;
    
    return (w->fd >= 0) ? 0 : -1;
}

/**
 * @brief 디스크 기록을 전담하는 워커 스레드 함수입니다.
 */
static inline void* writer_thread(void* arg){
    seg_writer_t* w = (seg_writer_t*)arg;
    const size_t ROLL = (size_t)1 << 30; /* 1GB마다 파일 롤링(새로 생성) */
    
    if (seg_open_new(w) != 0) return NULL;

    while (1){
        rx_item_t it;
        
        /* 큐에서 데이터 팝 (데이터가 들어올 때까지 블로킹됨) */
        if (rxq_pop(&g_rxq, &it) != 0) break;

        /* 기록할 데이터 길이(Body Len) 헤더 준비 (4바이트) */
        uint32_t body_len = (uint32_t)it.len;
        uint8_t  hdr[4];
        hdr[0] = (body_len >> 24) & 0xFF; 
        hdr[1] = (body_len >> 16) & 0xFF; 
        hdr[2] = (body_len >> 8) & 0xFF; 
        hdr[3] = body_len & 0xFF;

        /* writev를 사용하여 헤더와 바디를 원자적으로(함께) 기록 */
        struct iovec iov[2] = { 
            {hdr, 4}, 
            {(void*)it.buf, it.len} 
        };
        
        (void)writev(w->fd, iov, 2);
        w->bytes_in_seg += 4 + it.len;

        /* 기록 완료 후 버퍼 해제 */
        free(it.buf);

        /* 파일 크기가 ROLL 임계값을 넘으면 새로운 파일로 전환 */
        if (w->bytes_in_seg >= ROLL){ 
            close(w->fd); 
            seg_open_new(w); 
        }
    }
    
    close(w->fd);
    return NULL;
}

#endif /* SERVER_WORKER_H */