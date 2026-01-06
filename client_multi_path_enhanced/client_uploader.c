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

    /* 연결이 끊어지는 중이라면 루프 종료 */
    if (cs >= picoquic_state_disconnecting && !st->closing) {
        LOGF("[LOOP] Connection lost, exiting loop to reconnect...");
        return PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP; 
    }
    if (cs >= picoquic_state_disconnecting || st->closing) return 0;

    /* 특정 이벤트 타이밍이 아닌 경우 스킵 */
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

    /* 2. 0번 경로(Path 0) 생존성 보장 */
    ensure_path0_alive(c);


    /* ------------------------------------------------------------
     * [3. 핵심 복구 로직] 와이파이 생존 확인 및 안전한 재연결
     * ------------------------------------------------------------ */
    
    int wlan_alive = 0;

    /* 현재 활성 경로 중 와이파이 IP(192.168.0.170)가 살아있는지 확인 */
    for (int i = 0; i < c->nb_paths; i++) {
        picoquic_path_t* p = c->path[i];
        if (p && p->first_tuple && p->first_tuple->challenge_verified) {
            struct sockaddr_in* la = (struct sockaddr_in*)&p->first_tuple->local_addr;
            if (la->sin_addr.s_addr == st->ip_wlan_be) {
                wlan_alive = 1;
                break;
            }
        }
    }

    /* 와이파이가 죽었고 + 마지막 시도 후 2초 지났으면 재시도 */
    /* 16개의 quic 허용 수치까지 도달하기 전에 초기화 작업도 포함됨*/
    static uint64_t last_probe_ts = 0;
    
    /* [RECOVERY] 와이파이 생존 확인 및 경로 상태 강제 진단 */
    if (!wlan_alive && (now - last_probe_ts > 2000000)) {
        LOGF("==========================================================");
        LOGF("[DIAG] Wi-Fi Down. Checking existing paths...");

        int wlan_path_idx = -1;
        for (int i = 0; i < c->nb_paths; i++) {
            if (c->path[i] && c->path[i]->first_tuple) {
                struct sockaddr_in* la = (struct sockaddr_in*)&c->path[i]->first_tuple->local_addr;
                if (la->sin_addr.s_addr == st->ip_wlan_be) {
                    wlan_path_idx = i; // 이미 엔진에 와이파이 경로가 존재함
                    break;
                }
            }
        }

        if (wlan_path_idx != -1) {
            /* [중요] 경로가 이미 있다면 새로 만들지 말고 챌린지만 다시 보냄 */
            LOGF("[DIAG] Wi-Fi path exists (ID:%d). Re-probing...", wlan_path_idx);
            picoquic_set_path_challenge(c, wlan_path_idx, now);
        } else {
            /* 경로가 아예 없을 때만 새로 생성 */
            LOGF("[DIAG] Wi-Fi path missing. Creating new probe...");
            struct sockaddr_in wlan_probe = {0};
            wlan_probe.sin_family = AF_INET;
            wlan_probe.sin_port = htons(55002);
            wlan_probe.sin_addr.s_addr = st->ip_wlan_be;
            picoquic_probe_new_path(c, (struct sockaddr*)&st->peerA, (struct sockaddr*)&wlan_probe, now);
        }

        last_probe_ts = now;
        LOGF("==========================================================");
    }

    /* [LOG] 루프 진입 시점 기록 */
    if (cb_mode == picoquic_packet_loop_ready) {
        LOGF("[DEBUG-LOOP] Packet loop ready. WLAN_IP=%x, USB_IP=%x", st->ip_wlan_be, st->ip_usb_be);
    }

    /* 4. 보조 경로(Hotspot) 초기화 (한 번만 실행) */
    /* [RECOVERY & PROBE 블록 강화] */
    if (st->has_local_alt && !st->didB && now - st->hs_done_ts > 500000) {
        char alt_ip_str[INET_ADDRSTRLEN];
        struct sockaddr_in* sa_alt = (struct sockaddr_in*)&st->local_alt;
        inet_ntop(AF_INET, &(sa_alt->sin_addr), alt_ip_str, INET_ADDRSTRLEN);

        LOGF("[PROBE-STEP1] Attempting Hotspot Probe. Target IP: %s:%d", 
             alt_ip_str, ntohs(sa_alt->sin_port));
        
        int probe_ret = picoquic_probe_new_path(c, (struct sockaddr*)&st->peerA, 
                                               (struct sockaddr*)&st->local_alt, now);
        
        if (probe_ret == 0) {
            LOGF("[PROBE-STEP2] Hotspot probe packet passed to Engine. Waiting for Server Response...");
            st->didB = 1;
        } else {
            LOGF("[PROBE-ERR] Engine rejected probe request. Error code: %d", probe_ret);
        }
    }

    /* [PATH 상세 모니터링] 1초마다 모든 경로의 '쌩' 상태를 출력 */
    static uint64_t last_diag_ts = 0;
    if (now - last_diag_ts > 1000000) {
        for (int i = 0; i < (int)c->nb_paths; i++) {
            picoquic_path_t* p = c->path[i];
            if (!p || !p->first_tuple) continue;
            
            struct sockaddr_in* la = (struct sockaddr_in*)&p->first_tuple->local_addr;
            LOGF("[PATH-STATUS] ID:%d | Local:%08x | Verified:%d | RTT:%lu ms | CongestionWindow:%lu",
                 i, la->sin_addr.s_addr, p->first_tuple->challenge_verified, 
                 (unsigned long)(p->smoothed_rtt/1000), p->cwin);
            
            /* [중요] 만약 핫스팟 주소인데 Verified가 0이라면 서버 응답이 안 온 것 */
            if (la->sin_addr.s_addr == st->ip_usb_be && !p->first_tuple->challenge_verified) {
                LOGF("[CRITICAL] Hotspot Path exists but NOT VERIFIED by server. Check Server Multipath Config.");
            }
        }
        last_diag_ts = now;
    }
    
    /* 5. Keep-alive (1초마다) */
    if (now - st->last_keepalive_us > ONE_SEC_US) {
        static const uint8_t ka = 0;
        for (int i = 0; i < c->nb_paths; i++) {
            if (path_verified_idx(c, i))
                picoquic_add_to_stream_with_ctx(c, 0, &ka, 1, 0, st);
        }
        st->last_keepalive_us = now;
    }

    /* 6. 카메라 프레임 전송 (기존 로직 유지) */

    int cam_len = 0;
    pthread_mutex_lock(&st->cam_mtx);

    if (st->cam_seq != st->last_sent_seq && st->cam_len > 0) {

        if (st->cap_cap < (size_t)st->cam_len) {

            uint8_t* tmp = realloc(st->cap_buf, st->cam_len);
            if (tmp) { st->cap_buf = tmp; st->cap_cap = st->cam_len; }
        }

        if (st->cap_buf) {

            memcpy(st->cap_buf, st->cam_buf, st->cam_len);
            cam_len = st->cam_len;
            st->last_sent_seq = st->cam_seq;
        }
    }

    pthread_mutex_unlock(&st->cam_mtx);

    if (cam_len > 0) {
        /* 경로 선택 및 전송 */
        pathsel_t sel[MAX_PATHS];
        int sc = 0;

        /* [수정] Verified 여부와 상관없이 '존재하는 모든 경로'를 후보에 넣습니다. */
        for (int i = 0; i < c->nb_paths; i++) {
            if (c->path[i] && c->path[i]->first_tuple) {
                sel[sc].idx = i;
                sel[sc].p = c->path[i];
                sel[sc].ip_be = ((struct sockaddr_in*)&c->path[i]->first_tuple->local_addr)->sin_addr.s_addr;
                sc++;
            }
        }

        if (sc > 0) {
            /* pick_primary_idx가 이제 셀룰러(grade 1)와 와이파이(grade 0)를 비교하여 선택합니다. */
            int k = pick_primary_idx(c, sel, sc, st->ip_wlan_be, st->ip_usb_be, 
                                &st->last_primary_idx, now, &st->last_switch_ts);
            
            /* choose_verified_or_fallback을 거치지 말고 직접 k를 사용하여 전송 */
            if (k >= 0) {
                size_t hlen = varint_enc(cam_len, st->lenb);
                send_on_path_safe(c, st, k, st->lenb, hlen, st->cap_buf, cam_len);
            }
        }
    }

    picoquic_set_app_wake_time(c, now + 10000);
    return 0;
}


/* ============================================================
 * [3] 메인 함수 (프로그램 진입점)
 * ============================================================ */

int main(int argc, char** argv){

    /* 0. 기본 네트워크 설정 및 인자 파싱 */
    const char* server_ip     = "165.229.169.116";
    const char* local_alt_ip  = "172.20.10.11";      // Hotspot (eth1 등)
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
    tp.is_multipath_enabled = 1; // 멀티패스 허용
    tp.initial_max_path_id  = 16; // quic 허용 id개수 2->16개로 변경
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

    int alt_port = 51021;
    int usb_port = 55002;

    /* 로컬 주소 정보 저장 (Path Probing 시 사용) */
    if (!store_local_ip(local_alt_ip, 0, &st.local_alt)) {
        st.has_local_alt = 1;
        ((struct sockaddr_in*)&st.local_alt)->sin_port = htons(alt_port);
    }
    if (!store_local_ip(local_usb_ip, 0, &st.local_usb)) {
        st.has_local_usb = 1;
        ((struct sockaddr_in*)&st.local_usb)->sin_port = htons(usb_port);
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

    /* 7. 메인 소켓 바인딩 부분 수정 */
    int sock_wlan = -1;
    int sock_alt  = -1;

    // Wi-Fi 소켓: IP가 유효할 때만 생성
    if (st.has_local_usb) {
        sock_wlan = make_bound_socket(local_usb_ip, usb_port);
        if (sock_wlan < 0) {
            LOGF("[WRN] Wi-Fi NIC가 없거나 바인딩 실패. 일단 계속 진행합니다.");
        }
    }

    // 핫스팟 소켓: IP가 유효할 때만 생성
    if (st.has_local_alt) {
        sock_alt = make_bound_socket(local_alt_ip, alt_port);
        if (sock_alt < 0) {
            LOGF("[WRN] Hotspot NIC가 없거나 바인딩 실패.");
        }
    }

    // 최소한 하나의 소켓은 있어야 함
    if (sock_wlan < 0 && sock_alt < 0) {
        LOGF("[ERR] 사용할 수 있는 네트워크 인터페이스가 하나도 없습니다.");
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
    // int ret = picoquic_packet_loop_v2(q, &lp, loop_cb, &st);

    // LOGF("[MAIN] packet loop exit: ret=%d", ret);

    int ret = 0;

    while (!st.closing) {

        /* 1. 연결 상태 확인 및 재연결 준비 */
        int state = st.cnx ? picoquic_get_cnx_state(st.cnx) : picoquic_state_disconnected;

        if (st.cnx == NULL || state >= picoquic_state_disconnecting) {
            
            LOGF("[MAIN] Reconnecting sequence started...");

            /* [핵심 수정 1] 기존 연결이 남아있다면 확실하게 메모리 해제 (좀비 방지) */
            if (st.cnx != NULL) {
                picoquic_delete_cnx(st.cnx);
                st.cnx = NULL;
            }

            /* [핵심 수정 2] 이전 연결의 "기억(State)"을 초기화 (Segfault 원인 제거) */
            /* 이 부분이 없으면 이전 스트림 ID를 재사용하려다 죽습니다. */
            memset(st.sid_per_path, 0, sizeof(st.sid_per_path)); // 스트림 ID 초기화
            memset(st.b, 0, sizeof(st.b));                       // 바인딩 정보 초기화
            st.is_ready = 0;
            st.didB = 0;
            st.didC = 0;
            st.last_primary_idx = -1;

            /* 2. 새로운 연결 생성 */
            st.cnx = picoquic_create_cnx(
                q, 
                picoquic_null_connection_id, 
                picoquic_null_connection_id,
                (struct sockaddr*)&peerA, 
                picoquic_current_time(),
                0, server_ip, "hq", 1
            );

            if (st.cnx) {
                picoquic_set_callback(st.cnx, client_cb, &st);
                picoquic_enable_keep_alive(st.cnx, 1);
                picoquic_start_client_cnx(st.cnx);
                LOGF("[MAIN] New connection object created.");
            } else {
                LOGF("[ERR] Failed to create connection, retrying in 2s...");
                usleep(2000000);
                continue;
            }
        }

        /* 3. 패킷 루프 실행 */
        ret = picoquic_packet_loop_v2(q, &lp, loop_cb, &st);

        /* 4. 루프가 종료되었을 때 (연결 유실 등) */
        if (st.closing) break;
        
        LOGF("[MAIN] Loop exit (ret=%d). Cleaning up and retrying in 2s...", ret);
        
        /* 너무 빠른 재시도 방지 */
        usleep(2000000);
    }


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