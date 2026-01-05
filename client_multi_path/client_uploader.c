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

static int loop_cb(
    picoquic_quic_t* quic,
    picoquic_packet_loop_cb_enum cb_mode,
    void* cb_ctx,
    void* callback_return
){
    (void)callback_return;

    tx_t* st = (tx_t*)cb_ctx;
    picoquic_cnx_t* c = st->cnx;
    uint64_t now = picoquic_get_quic_time(quic);

    /* 0. 기본 상태 확인 */
    if (!st || !c) return 0;

    picoquic_state_enum cs = picoquic_get_cnx_state(c);
    
    /* 연결이 끊어지는 중이거나 이미 종료된 경우 루프 종료 */
    if (cs >= picoquic_state_disconnecting || st->closing) {
        return 0;
    }

    /* 특정 이벤트 타이밍이 아닌 경우 스킵하여 리소스 절약 */
    if (cb_mode != picoquic_packet_loop_after_receive &&
        cb_mode != picoquic_packet_loop_after_send &&
        cb_mode != picoquic_packet_loop_ready) {
        return 0;
    }


    /* 1. 미검증 경로(unreached path) 보호 */
    /* Address Validation이 완료되지 않은 경로의 메트릭이 알고리즘에 영향을 주지 않도록 무효화합니다. */
    for (int i = 0; i < c->nb_paths; i++) {

        picoquic_path_t* p = c->path[i];

        if (!p || !p->first_tuple) continue;

        if (!p->first_tuple->challenge_verified) {
            p->smoothed_rtt = UINT64_MAX/2;
            p->rtt_min      = UINT64_MAX/2;
            p->receive_rate_estimate = 0;
            p->total_bytes_lost      = 0;
        }
    }


    /* 2. 핸드셰이크 완료 대기 */
    if (!hs_done(c)) {
        picoquic_set_app_wake_time(c, now + 5000);
        return 0;
    }

    /* 기본 전송 경로가 항상 살아있도록 유지 */
    ensure_path0_alive(c);


    /* 3. 핸드셰이크 이후 추가 경로 Probing (멀티패스 활성화) */
    /* 지정된 시차를 두고 보조 NIC(Alt)와 USB 경로의 연결을 시도합니다. */
    if (st->has_local_alt && !st->didB && now - st->hs_done_ts > 200000) {
        LOGF("[PROBE] probing ALT...");
        
        picoquic_probe_new_path(
            c,
            (struct sockaddr*)&st->peerA,
            (struct sockaddr*)&st->local_alt,
            now
        );
        
        st->didB = 1;
    }

    if (st->has_local_usb && !st->didC && now - st->hs_done_ts > 400000) {
        LOGF("[PROBE] probing USB...");

        picoquic_probe_new_path(
            c,
            (struct sockaddr*)&st->peerA,
            (struct sockaddr*)&st->local_usb,
            now
        );

        st->didC = 1;
    }


    /* 4. Keep-alive 송신 (검증된 모든 경로 대상) */
    /* 1초마다 모든 유효 경로에 짧은 데이터를 보내 연결 유지를 확인합니다. */
    if (now - st->last_keepalive_us > ONE_SEC_US) {
        
        static const uint8_t ka = 0;

        for (int i = 0; i < c->nb_paths; i++) {
            picoquic_path_t* p = c->path[i];

            if (!path_verified_ptr(p)){ 
                continue;
            }

            picoquic_add_to_stream_with_ctx(c, 0, &ka, 1, 0, st);
        }

        st->last_keepalive_us = now;
    }


    /* 5. 카메라 프레임 수집 (스레드 안전) */
    /* 카메라 스레드가 캡처한 최신 데이터를 뮤텍스 락을 사용하여 복사해옵니다. */
    int cam_len = 0;
    uint64_t cam_seq = 0;

    pthread_mutex_lock(&st->cam_mtx);
    cam_len = st->cam_len;
    cam_seq = st->cam_seq;

    /* 새 프레임이 없거나 데이터가 없는 경우 대기 */
    if (cam_seq == st->last_sent_seq || cam_len <= 0) {
        pthread_mutex_unlock(&st->cam_mtx);
        picoquic_set_app_wake_time(c, now + 5000);
        return 0;
    }

    /* 수집용 버퍼 크기가 작으면 재할당(Realloc) */
    if (st->cap_cap < (size_t)cam_len) {
        uint8_t* tmp = realloc(st->cap_buf, cam_len);

        if (!tmp) { 
            pthread_mutex_unlock(&st->cam_mtx); 
            return 0; 
        }

        st->cap_buf = tmp;
        st->cap_cap = cam_len;
    }

    /* 공유 버퍼의 데이터를 전송용 버퍼로 복사 */
    memcpy(st->cap_buf, st->cam_buf, cam_len);
    st->last_sent_seq = cam_seq;
    pthread_mutex_unlock(&st->cam_mtx);

    /* 프레임 길이를 QUIC Varint로 인코딩하여 헤더 준비 */
    size_t hlen = varint_enc(cam_len, st->lenb);


    /* 6. 경로 필터링 및 미검증 경로 재검증 시도 */
    pathsel_t sel[MAX_PATHS];
    int sc = 0;
    build_unique_verified_paths(c, sel, &sc);

    if (sc == 0) {
        picoquic_set_app_wake_time(c, now + 20000);
        return 0;
    }

    /* 검증되지 않은 경로는 계속 Challenge를 킥(Kick)하여 활성화를 시도합니다. */
    for (int i = 0; i < c->nb_paths; i++) {
        
        picoquic_path_t* p = c->path[i];
        
        if (!p || !p->first_tuple) continue;

        int in_sel = 0;
        
        for (int t = 0; t < sc; t++){
            if (sel[t].idx == i) {
                in_sel = 1;
                break; 
            }
        }
            
        if (!in_sel && !p->first_tuple->challenge_verified) {
            kick_path_verification(c, st, i);
        }
    }


    /* 7. 보조 경로 Warm-up (부드러운 Failback 대비) */
    /* 현재 주 경로가 아닌 다른 유효 경로들에도 소량의 데이터를 흘려 품질을 측정합니다. */
    static const uint8_t warm = 0xEE;
    
    for (int i = 0; i < sc; i++) {
        picoquic_path_t* p = sel[i].p;
        
        if (!p || !p->first_tuple) continue;

        if (p->first_tuple->challenge_verified &&
            sel[i].idx != st->last_primary_idx)
        {
            picoquic_add_to_stream_with_ctx(c, 0, &warm, 1, 0, st);
        }
    }


    /* 8. 주 경로(PRIMARY) 선택 알고리즘 가동 */
    /* Wi-Fi(wlan)를 우선하되 품질 열화 시 USB(핫스팟)로 전환합니다. */
    int k = pick_primary_idx(
        c, sel, sc,
        st->ip_wlan_be, st->ip_usb_be,
        &st->last_primary_idx,
        now,
        &st->last_switch_ts);

    /* 선택된 경로가 여전히 유효한지 확인하고 안되면 폴백 경로 선택 */
    k = choose_verified_or_fallback(c, k);

    if (k < 0) { 
        picoquic_set_app_wake_time(c, now + 20000); 
        return 0; 
    }

    /* 후보 리스트 구성: 주 경로를 최우선으로, 나머지는 순차적 백업 */
    int candidates[MAX_PATHS];
    int cc = 0;
    if (k >= 0) candidates[cc++] = k;

    for (int i = 0; i < sc; i++) {
        int idx = sel[i].idx;
        if (idx == k) continue;

        if (path_sane_for_send(c, idx)) {
            candidates[cc++] = idx;
        }
    }

    /* 후보가 없으면 대기 */
    if (cc == 0) {
        picoquic_set_app_wake_time(c, now + 20000);
        return 0;
    }


    /* 9~11. 프레임 전송 (장애 시 즉시 우회) */
    /* 선택된 주 경로로 전송을 시도하고, 실패 시 다음 후보 경로로 즉시 넘어갑니다. */
    int sent_ok = -1;

    for (int t = 0; t < cc; t++) {

        int try_idx = candidates[t];

        /* 경로 상태가 건전하지 않으면 검증 패킷만 던지고 스킵 */
        if (!path_sane_for_send(c, try_idx)) {
            static const uint8_t poke = 0x01;
            picoquic_add_to_stream_with_ctx(c, 0, &poke, 1, 0, st);
            continue;
        }

        /* affinity(경로 고정)를 포함하여 실제 데이터 송신 */
        int sr = send_on_path_safe(c, st, try_idx, st->lenb, hlen, st->cap_buf, cam_len);

        if (sr == 0) {
            /* 전송 성공 시 주 경로 인덱스 업데이트 및 종료 */
            st->last_primary_idx = try_idx;
            sent_ok = 0;
            break;
        }
    }

    if (sent_ok != 0) {
        picoquic_set_app_wake_time(c, now + 20000);
        return 0;
    }


    /* 12. 네트워크 모니터링 로그 (1초 간격 리포트) */
    static uint64_t last_log_us = 0;
    static size_t bytes_accum[MAX_PATHS] = {0};

    bytes_accum[k] += cam_len;

    if (now - last_log_us > ONE_SEC_US) {
        LOGF("[MON] time=%.2fs paths=%d", now / 1e6, c->nb_paths);

        for (int i = 0; i < c->nb_paths; i++) {
            picoquic_path_t* pp = c->path[i];
            if (!pp || !pp->first_tuple) continue;

            char lip[32];
            inet_ntop(AF_INET,
                &((struct sockaddr_in*)&pp->first_tuple->local_addr)->sin_addr,
                lip, sizeof lip);

            double mbps = (bytes_accum[i] * 8.0) / 1e6;
            LOGF("  path[%d] %s verified=%d %.2f Mb/s",
                i, lip, pp->first_tuple->challenge_verified, mbps);

            bytes_accum[i] = 0;
        }

        last_log_us = now;
    }

    /* 13. 다음 루프 실행 시점 예약 */
    picoquic_set_app_wake_time(c, now + 20000);
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
    tp.initial_max_data  = 64 * 1024 * 1024;
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