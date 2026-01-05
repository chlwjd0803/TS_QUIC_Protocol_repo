#ifndef INIT_H
#define INIT_H

/* [표준 라이브러리 헤더] */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>

/* [네트워크 및 동기화 헤더] */
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>

/* [picoquic 라이브러리 헤더] */
#include "picoquic.h"
#include "picoquic_utils.h"
#include "picoquic_packet_loop.h"
#include "qlog.h"
#include "picoquic_binlog.h"
#include "autoqlog.h"

/* [프로젝트 내부 헤더] */
#include "app_ctx.h"
#include "frame_assembler.h"

/* ============================================================
 * [1] 시스템 설정 및 매크로
 * ============================================================ */

/* I/O 큐 사용 여부 설정 */
#define USE_IO_QUEUE 1

/* 로그 레벨 설정 (0:ERR, 1:WARN, 2:INFO, 3:DBG) */
#ifndef LOG_LEVEL
#define LOG_LEVEL 2  
#endif

/* 로그 출력 매크로: 지정된 레벨 이상일 때만 출력 */
#define LOG_ERR(fmt, ...) do{ if (LOG_LEVEL>=0){ LOGF("[ERR] " fmt, ##__VA_ARGS__);} }while(0)
#define LOG_WRN(fmt, ...) do{ if (LOG_LEVEL>=1){ LOGF("[WRN] " fmt, ##__VA_ARGS__);} }while(0)
#define LOG_INF(fmt, ...) do{ if (LOG_LEVEL>=2){ LOGF("[INF] " fmt, ##__VA_ARGS__);} }while(0)
#define LOG_DBG(fmt, ...) do{ if (LOG_LEVEL>=3){ LOGF("[DBG] " fmt, ##__VA_ARGS__);} }while(0)

/* 모니터링 임계값 설정 */
#define LOG_EVERY_BYTES  (1*1024*1024ULL)  /* 1MB 수신마다 로그 기록 */
#define BACKLOG_SOFTCAP  (8*1024*1024ULL)  /* 8MB 이상 저장 대기 시 Drop 모드 검토 */


/* ============================================================
 * [2] 데이터 구조체 정의
 * ============================================================ */

/**
 * @brief 저장을 기다리는 하나의 작업 단위(Job)를 정의합니다.
 */
typedef struct {
    app_ctx_t* app;    /* 애플리케이션 컨텍스트 */
    uint8_t* buf;    /* 프레임 데이터 버퍼 */
    size_t     len;    /* 프레임 데이터 길이 */
} job_t;


/* ============================================================
 * [3] 전역 동기화 객체 (스텁/참조용)
 * ============================================================ */

/* 작업 큐 관리를 위한 전역 뮤텍스 및 조건 변수 */
static pthread_mutex_t qmtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  qcv  = PTHREAD_COND_INITIALIZER;


#endif /* INIT_H */