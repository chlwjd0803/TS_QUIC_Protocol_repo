// client_uploader.c — picoquic raw-stream Single-Path Uploader

#include "struct_type.h"
#include "net_tools.h"
#include "quic_helpers.h"
#include "path_algo.h"
#include "camera_task.h"

/* ============================================================
 * [1] 연결 상태 및 콜백 이벤트 처리
 * ============================================================ */

static void on_cb_event(picoquic_call_back_event_t ev, tx_t* st, picoquic_cnx_t* cnx)
{
    (void)cnx;
    switch (ev) {
        case picoquic_callback_ready:
            st->is_ready = 1;
            st->ready_ts_us = picoquic_current_time();
            st->hs_done_ts = picoquic_current_time();
            LOGF("[CB] handshake complete → ready");
            break;
        case picoquic_callback_close:
        case picoquic_callback_application_close:
            st->peer_close_seen = 1;   
            LOGF("[CB] connection closed");
            break;
        default:
            break;
    }
}

static int client_cb(picoquic_cnx_t* cnx, uint64_t stream_id, uint8_t* bytes, size_t length,
                    picoquic_call_back_event_t ev, void* ctx, void* stream_ctx)
{
    (void)stream_id; (void)bytes; (void)length; (void)stream_ctx;
    tx_t* st = (tx_t*)ctx;
    if (st) on_cb_event(ev, st, cnx);
    return 0;
}

/* ============================================================
 * [2] 패킷 루프 콜백 (Single-Path 전송 로직)
 * ============================================================ */

static int loop_cb(picoquic_quic_t* quic, picoquic_packet_loop_cb_enum cb_mode,
                   void* cb_ctx, void* callback_return)
{
    (void)callback_return;
    tx_t* st = (tx_t*)cb_ctx;
    picoquic_cnx_t* c = st->cnx;
    uint64_t now = picoquic_get_quic_time(quic);

    if (!st || !c) return 0;

    picoquic_state_enum cs = picoquic_get_cnx_state(c);
    if (cs >= picoquic_state_disconnecting || st->closing) return 0;

    if (cb_mode != picoquic_packet_loop_after_receive &&
        cb_mode != picoquic_packet_loop_after_send &&
        cb_mode != picoquic_packet_loop_ready) {
        return 0;
    }

    /* 1. 핸드셰이크 완료 대기 */
    if (!hs_done(c)) {
        picoquic_set_app_wake_time(c, now + 5000);
        return 0;
    }

    /* 2. Keep-alive (0번 경로 유지) */
    if (now - st->last_keepalive_us > ONE_SEC_US) {
        static const uint8_t ka = 0;
        if (path_verified_idx(c, 0)) {
            picoquic_add_to_stream_with_ctx(c, 0, &ka, 1, 0, st);
        }
        st->last_keepalive_us = now;
    }

    /* 3. 카메라 프레임 수집 */
    int cam_len = 0;
    uint64_t cam_seq = 0;

    pthread_mutex_lock(&st->cam_mtx);
    cam_len = st->cam_len;
    cam_seq = st->cam_seq;

    if (cam_seq == st->last_sent_seq || cam_len <= 0) {
        pthread_mutex_unlock(&st->cam_mtx);
        picoquic_set_app_wake_time(c, now + 5000);
        return 0;
    }

    if (st->cap_cap < (size_t)cam_len) {
        uint8_t* tmp = realloc(st->cap_buf, cam_len);
        if (!tmp) { pthread_mutex_unlock(&st->cam_mtx); return 0; }
        st->cap_buf = tmp;
        st->cap_cap = cam_len;
    }

    memcpy(st->cap_buf, st->cam_buf, cam_len);
    st->last_sent_seq = cam_seq;
    pthread_mutex_unlock(&st->cam_mtx);

    size_t hlen = varint_enc(cam_len, st->lenb);

    /* 4. 데이터 전송 (항상 0번 경로 사용) */
    int sent_ok = -1;
    const int target_idx = 0; // k와 cc 대신 고정된 인덱스 사용

    if (path_sane_for_send(c, target_idx)) {
        int sr = send_on_path_safe(c, st, target_idx, st->lenb, hlen, st->cap_buf, cam_len);
        if (sr == 0) {
            sent_ok = 0;
        }
    }

    if (sent_ok != 0) {
        picoquic_set_app_wake_time(c, now + 20000);
        return 0;
    }

    /* 5. 네트워크 모니터링 로그 (Single-Path용) */
    static uint64_t last_log_us = 0;
    static size_t bytes_accum = 0;
    bytes_accum += cam_len;

    if (now - last_log_us > ONE_SEC_US) {
        double mbps = (bytes_accum * 8.0) / 1e6;
        LOGF("[MON] Single-Path[0] Total: %.2f Mb/s", mbps);
        bytes_accum = 0;
        last_log_us = now;
    }

    picoquic_set_app_wake_time(c, now + 20000);
    return 0;
}

int main(int argc, char** argv){
    const char* server_ip = "192.168.0.83";
    const char* local_ip  = "192.168.0.170"; 
    int port = 4433;

    if (argc > 1) server_ip = argv[1];
    if (argc > 2) local_ip  = argv[2];
    if (argc > 3) port      = atoi(argv[3]);

    picoquic_quic_t* q = picoquic_create(32, NULL, NULL, NULL, "hq", NULL, NULL, NULL, NULL, NULL,
                                        picoquic_current_time(), NULL, NULL, NULL, 1);

    picoquic_tp_t tp;
    memset(&tp, 0, sizeof(tp));
    picoquic_init_transport_parameters(&tp, 0);
    tp.is_multipath_enabled = 0; // 멀티패스 비활성화
    picoquic_set_default_tp(q, &tp);

    struct sockaddr_storage peerA = {0};
    resolve_ip(server_ip, port, &peerA);

    picoquic_cnx_t* cnx = picoquic_create_cnx(q, picoquic_null_connection_id, picoquic_null_connection_id,
                                            (struct sockaddr*)&peerA, picoquic_current_time(), 0, server_ip, "hq", 1);

    tx_t st;
    memset(&st, 0, sizeof(st));
    st.cnx = cnx;
    pthread_mutex_init(&st.cam_mtx, NULL);

    picoquic_set_callback(cnx, client_cb, &st);
    picoquic_start_client_cnx(cnx);

    st.cam = camera_create();
    pthread_create(&st.cam_thread, NULL, camera_thread_main, &st);
    st.cam_thread_started = 1;

    int sock = make_bound_socket(local_ip, 55002);

    picoquic_packet_loop_param_t lp = {0};
    lp.local_af = AF_INET;
    lp.extra_socket_required = 1;

    picoquic_packet_loop_v2(q, &lp, loop_cb, &st);

    // 정리 로직 생략 (기존과 동일)
    return 0;
}