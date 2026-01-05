#ifndef CAMERA_TASK_H
#define CAMERA_TASK_H

#include "struct_type.h"
#include "net_tools.h"
#include "quic_helpers.h"
#include "path_algo.h"

/**
 * @brief 카메라 캡처를 담당하는 백그라운드 스레드의 메인 함수입니다.
 * * 이 스레드는 독립적으로 실행되며, 카메라로부터 MJPEG/JPEG 프레임을 읽어와
 * tx_t 구조체의 공유 버퍼(cam_buf)에 저장합니다.
 */
static void* camera_thread_main(void* arg)
{
    tx_t* st = (tx_t*)arg;
    
    LOGF("[CAM] thread started");

    /* st->cam_stop 플래그가 1이 될 때까지 무한 루프 수행 */
    while (!st->cam_stop) {

        /* 0. 카메라 객체가 아직 생성되지 않았다면 잠시 대기 */
        if (!st->cam) {
            usleep(10000);  // 10ms 대기
            continue;
        }

        /* 1. 캡처용 공유 버퍼 용량 확보 */
        /* 초기 상태이거나 버퍼가 너무 작으면 최소 1MB(1u << 20)로 확장합니다. */
        if (st->cam_cap < (1u << 20)) {

            uint8_t* tmp = (uint8_t*)realloc(st->cam_buf, 1u << 20);

            if (!tmp) {
                LOGF("[CAM] realloc failed");
                usleep(10000);
                continue;
            }

            st->cam_buf = tmp;
            st->cam_cap = 1u << 20;
        }

        /* 2. 실제 카메라 프레임 캡처 (블로킹 모드) */
        /* camera_capture_jpeg 함수를 통해 JPEG 데이터를 cam_buf에 직접 씁니다. */
        int n = camera_capture_jpeg(st->cam, st->cam_buf, (int)st->cam_cap);
        
        /* 캡처 실패 또는 비정상적인 크기일 경우 스킵 */
        if (n <= 0 || (size_t)n > st->cam_cap) {
            // 실패 시 CPU 점유율 방지를 위해 짧게 휴식할 수 있으나, 
            // 여기서는 원본 로직에 따라 즉시 다음 루프로 진입합니다.
            continue;
        }

        /* 3. 공유 자원 업데이트를 위한 뮤텍스 락(Lock) */
        /* 메인 루프(loop_cb)가 최신 프레임을 인지할 수 있도록 메타데이터만 보호합니다. */
        pthread_mutex_lock(&st->cam_mtx);
        
        st->cam_len = n;      // 캡처된 데이터의 실제 길이 업데이트
        st->cam_seq++;        // 프레임 시퀀스 번호 증가 (새 데이터가 왔음을 알림)
        
        pthread_mutex_unlock(&st->cam_mtx);
        
        /* * 이 시점에서 loop_cb(메인 루프)는 st->cam_seq의 변화를 감지하고
         * 이 cam_buf의 내용을 자신의 전송 버퍼로 복사하여 전송하게 됩니다.
         */
    }

    LOGF("[CAM] thread exit");
    
    return NULL;
}

#endif