// client_uploader.c — picoquic raw-stream MP Uploader (Wi-Fi + Hotspot)

#include "struct_type.h"
#include "net_tools.h"
#include "quic_helpers.h"
#include "path_algo.h"
#include "camera_task.h"

/* ============================================================
 * [1] 연결 상태 및 콜백 이벤트 처리
 * ============================================================ */

/**
 * @brief picoquic 연결 이벤트(핸드셰이크 완료, 종료 등)를 처리합니다.
 */
static void on_cb_event(picoquic_call_back_event_t ev, tx_t* st, picoquic_cnx_t* cnx)
{
    (void)cnx;

    switch (ev) {

        case picoquic_callback_ready:
            /* 핸드셰이크가 성공적으로 완료되어 데이터 전송 준비가 됨 */
            st->is_ready = 1;
            st->ready_ts_us = picoquic_current_time();
            st->hs_done_ts = picoquic_current_time();
            LOGF("[CB] handshake complete → ready");
            break;

        case picoquic_callback_close:
        case picoquic_callback_application_close:
            /* 연결 종료 신호를 수신했을 때 기록만 남기고 테스트 루프는 유지 */
            st->peer_close_seen = 1;   
            LOGF("[CB] closing (IGNORED for test; keeping loop alive)");
            break;

        default:
            break;
    }
}

/**
 * @brief picoquic의 기본 애플리케이션 콜백 함수입니다.
 */
static int client_cb(
    picoquic_cnx_t* cnx, uint64_t stream_id,
    uint8_t* bytes, size_t length,
    picoquic_call_back_event_t ev, void* ctx,
    void* stream_ctx
){
    (void)stream_id; (void)bytes; (void)length; (void)stream_ctx;
    
    tx_t* st = (tx_t*)ctx;
    if (st) {
        on_cb_event(ev, st, cnx);
    }
    
    return 0;
}


/* ============================================================
 * [2] 패킷 루프 콜백 (핵심 전송 및 모니터링 로직)
 * ============================================================ */

static int loop_cb(picoquic_quic_t* quic, picoquic_packet_loop_cb_enum cb_mode, 
                  void* cb_ctx, void* callback_return) {
    tx_t* st = (tx_t*)cb_ctx;
    picoquic_cnx_t* c = st->cnx;
    uint64_t now = picoquic_get_quic_time(quic);

    if (!st || !c || st->closing) return 0;
    if (cb_mode == picoquic_packet_loop_wake_up) return 0;

    /* 1. 핸드셰이크 가드 및 경로 생존 확인 (최소한의 오버헤드) */
    if (!hs_done(c)) {
        picoquic_set_app_wake_time(c, now + 10000);
        return 0;
    }

    /* 2. [방법 A+ 최적화] 경로 관리 전체를 100ms 주기로 격리 */
    static uint64_t last_eval_ts = 0;
    static int cached_k = 0;
    static pathsel_t sel[MAX_PATHS];
    static int sc = 0;

    if (now - last_eval_ts > 100000 || cached_k == -1) {
        // 경로 목록 빌드와 최적 경로 선택을 모두 100ms에 한 번만 수행
        build_unique_verified_paths(c, sel, &sc);
        
        if (sc > 0) {
            cached_k = pick_primary_idx(
                c, sel, sc,
                st->ip_wlan_be, st->ip_usb_be,
                &st->last_primary_idx,
                now,
                &st->last_switch_ts);
        }
        last_eval_ts = now;
    }
    
    // 만약 검증된 경로가 하나도 없다면 대기
    if (sc == 0) {
        picoquic_set_app_wake_time(c, now + 50000);
        return 0;
    }

    /* 3. [방법 C+ 최적화] 포인터 스와핑을 통한 제로 카피 지향 */
    uint8_t* data_to_send = NULL;
    int cam_len = 0;

    pthread_mutex_lock(&st->cam_mtx);
    if (st->cam_seq != st->last_sent_seq && st->cam_len > 0) {
        /* [핵심] memcpy 대신 포인터를 교체합니다. 
           네트워크 루프는 cap_buf를 쓰고, 카메라 스레드는 cam_buf를 쓰도록 서로 바꿉니다. */
        uint8_t* tmp = st->cap_buf;
        st->cap_buf = st->cam_buf;
        st->cam_buf = tmp;
        
        // 버퍼 크기 정보도 동기화
        size_t tmp_cap = st->cap_cap;
        st->cap_cap = st->cam_cap;
        st->cam_cap = tmp_cap;

        st->last_sent_seq = st->cam_seq;
        data_to_send = st->cap_buf;
        cam_len = st->cam_len;
    }
    pthread_mutex_unlock(&st->cam_mtx);

    if (!data_to_send) {
        picoquic_set_app_wake_time(c, now + 5000);
        return 0;
    }

    /* 4. 데이터 전송 준비 */
    size_t hlen = varint_enc(cam_len, st->lenb);
    int k = choose_verified_or_fallback(c, cached_k);

    /* 5. [방법 B] 전송 (Affinity 최적화는 quic_helpers.h의 send_on_path_safe에 적용됨) */
    // Failover 후보군 생성
    int candidates[2], cc = 0;
    candidates[cc++] = k;
    if (sc > 1) { // 보조 경로가 있다면 추가
        int alt_idx = (sel[0].idx == k) ? sel[1].idx : sel[0].idx;
        candidates[cc++] = alt_idx;
    }

    for (int t = 0; t < cc; t++) {
        if (send_on_path_safe(c, st, candidates[t], st->lenb, hlen, data_to_send, cam_len) == 0) {
            break;
        }
    }

    // 다음 프레임을 위해 즉시 또는 짧게 대기
    picoquic_set_app_wake_time(c, now + 2000); 
    return 0;
}


/* ============================================================
 * [3] 메인 함수 (프로그램 진입점)
 * ============================================================ */

int main(int argc, char** argv){

    /* 0. 기본 네트워크 설정 및 인자 파싱 */
    const char* server_ip     = "192.168.0.83";
    const char* local_alt_ip  = "192.168.0.170";      // Hotspot (eth1 등)
    const char* local_usb_ip  = "192.168.0.170";      // Wi-Fi (wlan0 등)
    int port = 4433;

    if (argc > 1 && argv[1][0]) server_ip     = argv[1];
    if (argc > 2 && argv[2][0]) local_alt_ip  = argv[2];
    if (argc > 3 && argv[3][0]) port          = atoi(argv[3]);
    if (argc > 4 && argv[4][0]) local_usb_ip  = argv[4];

    LOGF("[MAIN] args: server=%s port=%d alt=%s usb=%s",
         server_ip, port, local_alt_ip, local_usb_ip);


    /* 1. picoquic 컨텍스트 생성 및 멀티패스 TP 설정 */
    LOGF("[MAIN] creating QUIC ctx...");

    picoquic_quic_t* q = picoquic_create(
        32, NULL, NULL, NULL, "hq",
        NULL, NULL, NULL, NULL, NULL,
        picoquic_current_time(),
        NULL, NULL, NULL,
        1 /* use_pmtud */
    );

    if (!q) {
        LOGF("[ERR] picoquic_create failed");
        return -1;
    }

    /* 전송 파라미터(TP) 설정: 멀티패스 및 버퍼 크기 최적화 */
    picoquic_tp_t tp;
    memset(&tp, 0, sizeof(tp));
    picoquic_init_transport_parameters(&tp, 0);
    tp.is_multipath_enabled = 3;
    tp.initial_max_path_id  = 2;
    tp.active_connection_id_limit = 8;
    tp.initial_max_data  = 128 * 1024 * 1024; // 128로 용량 조정
    tp.initial_max_stream_data_uni = 8 * 1024 * 1024;
    picoquic_set_default_tp(q, &tp);


    /* 2. 서버 주소 해석(Resolve) */
    struct sockaddr_storage peerA = {0};
    if (resolve_ip(server_ip, port, &peerA) != 0) {
        LOGF("[ERR] resolve server failed");
        return -1;
    }


    /* 3. QUIC 연결(Connection) 생성 */
    picoquic_cnx_t* cnx = picoquic_create_cnx(
        q,
        picoquic_null_connection_id, picoquic_null_connection_id,
        (struct sockaddr*)&peerA,
        picoquic_current_time(),
        0, server_ip, "hq",
        1
    );

    if (!cnx) {
        LOGF("[ERR] create_cnx failed");
        picoquic_free(q);
        return -1;
    }

    picoquic_enable_keep_alive(cnx, 1);


    /* 4. 업로더 상태 구조체(tx_t) 초기화 */
    tx_t st;
    memset(&st, 0, sizeof(st));

    st.cnx = cnx;
    st.rr  = -1;
    st.peerA = peerA;

    st.ip_wlan_be = inet_addr(local_usb_ip); 
    st.ip_usb_be  = inet_addr(local_alt_ip); 
    st.last_primary_idx = -1;
    st.last_switch_ts   = 0;
    pthread_mutex_init(&st.cam_mtx, NULL);

    /* 로컬 주소 정보 저장 (Path Probing 시 사용) */
    if (!store_local_ip(local_alt_ip, 0, &st.local_alt)) {
        st.has_local_alt = 1;
        ((struct sockaddr_in*)&st.local_alt)->sin_port = htons(55001);
    }

    if (!store_local_ip(local_usb_ip, 0, &st.local_usb)) {
        st.has_local_usb = 1;
        ((struct sockaddr_in*)&st.local_usb)->sin_port = htons(55002);
    }


    /* 5. 콜백 등록 및 클라이언트 시작 */
    picoquic_set_callback(cnx, client_cb, &st);

    if (picoquic_start_client_cnx(cnx) != 0) {
        LOGF("[ERR] start_client_cnx failed");
        picoquic_free(q);
        return -1;
    }


    /* 6. 카메라 및 캡처 스레드 시작 */
    st.cam = camera_create();
    if (!st.cam) {
        LOGF("[ERR] camera_create failed");
        picoquic_free(q);
        return -1;
    }

    if (pthread_create(&st.cam_thread, NULL, camera_thread_main, &st) == 0) {
        st.cam_thread_started = 1;
    }


    /* 7. 메인 소켓 바인딩 (Wi-Fi NIC 강제 고정) */
    LOGF("[MAIN] binding main socket to Wi-Fi NIC...");

    int sock_wlan = make_bound_socket(local_usb_ip, 55002);

    if (sock_wlan < 0) {
        LOGF("[ERR] make_bound_socket failed");
        return -1;
    }


    /* 8. 패킷 루프 파라미터 설정 */
    picoquic_packet_loop_param_t lp;
    memset(&lp, 0, sizeof(lp));

    lp.local_af = AF_INET;
    lp.extra_socket_required = 1;
    lp.do_not_use_gso = 1;

    LOGF("[MAIN] entering packet loop...");


    /* 9. 패킷 루프 실행 (picoquic 구동) */
    int ret = picoquic_packet_loop_v2(q, &lp, loop_cb, &st);

    LOGF("[MAIN] packet loop exit: ret=%d", ret);


    /* 10. 자원 해제 및 종료 정리 */
    if (st.cam_thread_started) {
        st.cam_stop = 1;
        pthread_join(st.cam_thread, NULL);
    }

    pthread_mutex_destroy(&st.cam_mtx);

    if (st.cam) camera_destroy(st.cam);
    if (st.cam_buf) free(st.cam_buf);
    if (st.cap_buf) free(st.cap_buf);

    if (sock_wlan > 0) close(sock_wlan);
    picoquic_free(q);

    LOGF("[MAIN] freed all, exit=%d", ret);
    return ret;
}