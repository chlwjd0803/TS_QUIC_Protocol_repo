// frame_assembler.h
#ifndef FRAME_ASSEMBLER_H
#define FRAME_ASSEMBLER_H

#include <stddef.h>
#include <stdint.h>
#include "app_ctx.h"
#include "picoquic_internal.h"

/* ============================================================
 * [1] 프레임 조립 및 처리 인터페이스
 * ============================================================ */

/**
 * @brief 수신된 바이트 데이터를 해석하여 프레임으로 조립합니다.
 * * @param cnx picoquic 연결 객체
 * @param app 애플리케이션 컨텍스트
 * @param sid 스트림 ID
 * @param bytes 수신된 데이터 포인터
 * @param length 수신된 데이터 길이
 * @return int 성공 시 0, 실패 시 음수 값
 */
int fa_on_bytes(picoquic_cnx_t* cnx, app_ctx_t* app, uint64_t sid,
                const uint8_t* bytes, size_t length);


/**
 * @brief 조립이 완료된 프레임을 디스크에 저장하기 위해 큐에 넣습니다.
 * * @param app 애플리케이션 컨텍스트
 * @param data 프레임 데이터 포인터
 * @param len 프레임 데이터 길이
 * @return int 저장 성공(0), 실패(<0)
 */
int save_frame(app_ctx_t* app, const uint8_t* data, size_t len);


/* ============================================================
 * [2] 스트림 관리 및 자원 정리
 * ============================================================ */

/**
 * @brief 특정 스트림의 조립 상태를 초기화합니다.
 * * @param rx 수신 스트림 상태 구조체 포인터
 */
void rx_clear(rx_stream_t* rx);


/**
 * @brief 특정 스트림이 닫힐 때 관련된 자원을 해제하고 상태를 정리합니다.
 * * @param app 애플리케이션 컨텍스트
 * @param sid 닫을 스트림 ID
 */
void fa_stream_close(app_ctx_t* app, uint64_t sid);

#endif /* FRAME_ASSEMBLER_H */