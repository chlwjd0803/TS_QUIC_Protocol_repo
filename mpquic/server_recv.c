// server_recv.c — picoquic raw-stream receiver (MP OK, no WebTransport)

#include "init.h"
#include "server_utils.h"
#include "server_worker.h"
#include "server_legacy.h"

/* ============================================================
 * [1] 스트림 데이터 수신 콜백 (애플리케이션 로직)
 * ============================================================ */

/**
 * @brief 각 스트림을 통해 들어오는 데이터를 처리하는 콜백 함수입니다.
 */
static int stream_cb(picoquic_cnx_t* cnx, uint64_t sid, uint8_t* bytes, size_t len,
                     picoquic_call_back_event_t ev, void* cb_ctx, void* v_stream_ctx)
{
    (void)v_stream_ctx;
    app_ctx_t* app = (app_ctx_t*)cb_ctx;

    /* 수신량 로그 출력 제어 (64KB 누적 시마다 한 줄 출력) */
    static uint64_t log_accum = 0;
    log_accum += len;
    
    if (log_accum >= (64 * 1024)){
        LOG_INF("[RX] ev=%d sid=%" PRIu64 " chunk=%zuB (accum+=%" PRIu64 ")", ev, sid, len, log_accum);
        log_accum = 0;
    }

    switch (ev) {
    case picoquic_callback_stream_data:
    case picoquic_callback_stream_fin: {
        
        if (len > 0) {
            static uint64_t last_log_bytes = 0;
            
            if (app) app->bytes_rx_total += len;
            
            /* 대량 데이터 수신 시 주기적으로 덤프 및 정보 출력 */
            if (app && app->bytes_rx_total - last_log_bytes >= LOG_EVERY_BYTES) {
                LOG_INF("[RX] sid=%" PRIu64 " +%zuB (total=%" PRIu64 ")", sid, len, app->bytes_rx_total);
                dump_prefix(bytes, len, 16);
                last_log_bytes = app->bytes_rx_total;
            }

            /* I/O 백로그(저장 대기량)가 너무 많으면 데이터를 버리는(Drop) 모드 작동 */
            int drop_mode = 0;
            if (app && app->backlog_bytes > BACKLOG_SOFTCAP) drop_mode = 1;
            
            const char* dm = getenv("SVR_DROP_MODE");
            if (!drop_mode && dm && *dm == '1') drop_mode = 1;

            int r = 0;
            if (!drop_mode) {
                /* 실제 프레임 조립 로직 호출 */
                r = fa_on_bytes(cnx, app, sid, bytes, len);
                
                if (r != 0) {
                    LOG_WRN("[RX] fa_on_bytes ret=%d (sid=%" PRIu64 ", len=%zu)", r, sid, len);
                }
            }
        }

        /* 스트림 종료(FIN) 처리 */
        if (ev == picoquic_callback_stream_fin) {
            fa_stream_close(app, sid);
            LOG_INF("[STREAM] FIN sid=%" PRIu64, sid);
        }

        /* 최대 프레임 수신 제한 도달 시 연결 종료 */
        if (app && app->max_frames > 0 && app->frame_count >= app->max_frames) {
            LOG_INF("[LIMIT] reached max_frames=%d → connection close", app->max_frames);
            picoquic_close(cnx, 0);
        }
        return 0;
    }

    case picoquic_callback_stream_reset:
        fa_stream_close(app, sid);
        LOG_WRN("[STREAM] RESET sid=%" PRIu64, sid);
        return 0;

    case picoquic_callback_stop_sending:
        fa_stream_close(app, sid);
        LOG_WRN("[STREAM] STOP_SENDING sid=%" PRIu64, sid);
        return 0;

    default:
        return 0;
    }
}


/* ============================================================
 * [2] 패킷 루프 콜백 (연결 및 경로 모니터링)
 * ============================================================ */

static int loop_cb(picoquic_quic_t* quic,
                   picoquic_packet_loop_cb_enum cb_mode,
                   void* cb_ctx, void* callback_return)
{
    (void)callback_return;
    app_ctx_t* app = (app_ctx_t*)cb_ctx;

    static uint64_t last_paths_dump_us = 0;
    static picoquic_state_enum last_state = (picoquic_state_enum)-1;

    if (cb_mode == picoquic_packet_loop_ready) {
        LOG_INF("[LOOP] QUIC ready, waiting for connections...");
    }

    /* 모든 연결(Connection)을 순회하며 상태 및 경로 정보를 출력 */
    for (picoquic_cnx_t* c = picoquic_get_first_cnx(quic);
         c != NULL; c = picoquic_get_next_cnx(c))
    {
        /* 콜백 컨텍스트가 없으면 애플리케이션 컨텍스트 설정 */
        if (picoquic_get_callback_context(c) == NULL) {
            picoquic_set_callback(c, stream_cb, app);
        }

        /* 연결 상태 변경 시 로그 출력 */
        picoquic_state_enum cs = picoquic_get_cnx_state(c);
        if (cs != last_state){
            struct sockaddr* sa = NULL; 
            picoquic_get_peer_addr(c, &sa);
            
            char hp[128] = {0}; 
            addr_to_str(sa, hp, sizeof(hp));
            
            LOG_INF("[CNX] state=%s nb_paths=%d peer=%s",
                    cnx_state_str(cs), (int)c->nb_paths, hp);
            last_state = cs;
        }

        /* 연결이 준비(READY)되면 정보 출력 */
        if (!cnx_marked_printed(c) && cs == picoquic_state_ready) {
            struct sockaddr* sa = NULL; 
            picoquic_get_peer_addr(c, &sa);
            
            char hp[128] = {0}; 
            addr_to_str(sa, hp, sizeof(hp));
            
            LOG_INF("[CNX] READY peer=%s (paths=%d)", hp, (int)c->nb_paths);
            cnx_mark_set(c);
        }

        /* 2초마다 경로(Path) 상세 정보 덤프 */
        uint64_t now = picoquic_current_time();
        if (now - last_paths_dump_us > 2 * 1000000ULL) {
            for (int i = 0; i < (int)c->nb_paths; i++){
                picoquic_path_t* p = c->path[i];
                if (!p) continue;
                LOG_DBG("[PATH] i=%d present=1", i);
            }
            last_paths_dump_us = now;
        }
    }

    /* 송수신 완료 후 2ms 뒤에 다시 깨어나도록 설정 (반응성 유지) */
    if (cb_mode == picoquic_packet_loop_after_receive ||
        cb_mode == picoquic_packet_loop_after_send)
    {
        for (picoquic_cnx_t* c = picoquic_get_first_cnx(quic);
             c != NULL; c = picoquic_get_next_cnx(c))
        {
            picoquic_set_app_wake_time(c, picoquic_current_time() + 2000);
        }
    }

    return 0;
}


/* ============================================================
 * [3] CLI 도움말 및 메인 함수
 * ============================================================ */

static void usage(const char* argv0){
    fprintf(stderr,
        "Usage: %s [--port N] [--cert path] [--key path] [--qlog] [--binlog]\n"
        "          [--out DIR] [--max-frames N]\n", argv0);
}

int main(int argc, char** argv)
{
    /* 기본 설정값 */
    int port = DEFAULT_PORT;
    const char* cert = DEFAULT_CERT;
    const char* key  = DEFAULT_KEY;
    int enable_qlog = 0, enable_binlog = 0;

    app_ctx_t app; 
    memset(&app, 0, sizeof(app));
    
    snprintf(app.out_dir, sizeof(app.out_dir), "%s", "frames_out");
    app.max_frames = 0; 

    /* 1. 명령행 인자 파싱 */
    for (int i = 1; i < argc; i++){
        if (!strcmp(argv[i], "--port") && i + 1 < argc){
            port = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--cert") && i + 1 < argc){
            cert = argv[++i];
        } else if (!strcmp(argv[i], "--key") && i + 1 < argc){
            key = argv[++i];
        } else if (!strcmp(argv[i], "--qlog")){
            enable_qlog = 1;
        } else if (!strcmp(argv[i], "--binlog")){
            enable_binlog = 1;
        } else if (!strcmp(argv[i], "--out") && i + 1 < argc){
            snprintf(app.out_dir, sizeof(app.out_dir), "%s", argv[++i]);
        } else if (!strcmp(argv[i], "--max-frames") && i + 1 < argc){
            app.max_frames = atoi(argv[++i]);
        } else {
            usage(argv[0]);
            return -1;
        }
    }
    
    LOGF("[SVR][MAIN] args: port=%d cert=%s key=%s out=%s max_frames=%d",
         port, cert, key, app.out_dir, app.max_frames);


    /* 2. QUIC 컨텍스트 생성 */
    LOGF("[SVR][MAIN] creating QUIC ctx (ALPN=hq)...");
    
    picoquic_quic_t* quic = picoquic_create(
        64, cert, key, NULL, "hq",
        stream_cb, &app, NULL, NULL, NULL,
        picoquic_current_time(), NULL, NULL, NULL, 1);
        
    if (!quic){
        LOGF("[SVR][ERR] picoquic_create failed");
        return -1;
    }


    /* 3. 전송 파라미터(TP) 설정 (서버 측) */
    picoquic_tp_t tp; 
    memset(&tp, 0, sizeof(tp));
    picoquic_init_transport_parameters(&tp, 1); 

    tp.is_multipath_enabled    = 1;   /* 0 -> 1 : 멀티패스 공식 활성화 */
    tp.initial_max_path_id     = 16;  /* 3 -> 16 : 경로 ID 제한 대폭 해제 (클라이언트와 동일하게) */
    tp.enable_time_stamp       = 3;
    tp.max_datagram_frame_size = 1200;
    tp.active_connection_id_limit = 8; /* 4 -> 8 : 넉넉하게 늘림 */
    
    /* 대용량 영상 전송을 위해 수신 윈도우를 넉넉하게 설정 */
    tp.initial_max_data = 8 * 1024 * 1024; 
    tp.initial_max_stream_data_bidi_local  = 128 * 1024 * 1024;
    tp.initial_max_stream_data_bidi_remote = 128 * 1024 * 1024;
    tp.initial_max_stream_data_uni         = 128 * 1024 * 1024;

    tp.initial_max_stream_id_bidir  = 64;
    tp.initial_max_stream_id_unidir = 64;
    
    /* 지연 감소를 위해 ACK 딜레이 최소화 */
    tp.max_ack_delay      = 0;  
    tp.ack_delay_exponent = 3;

    picoquic_set_default_tp(quic, &tp);


    /* 4. 비동기 저장 스레드(Writer) 시작 */
    seg_writer_t w = { .fd = -1, .bytes_in_seg = 0 };
    snprintf(w.dir, sizeof(w.dir), "%s", app.out_dir);
    
    ensure_dir(w.dir);
    
    pthread_t wth; 
    pthread_create(&wth, NULL, writer_thread, &w);


    /* 5. 패킷 루프 설정 및 실행 */
    picoquic_packet_loop_param_t lp = (picoquic_packet_loop_param_t){0};
    lp.local_port = port;
    lp.extra_socket_required = 1;
    lp.socket_buffer_size = 4 * 1024 * 1024; /* 소켓 버퍼 확장 */
    lp.do_not_use_gso = 0;

    LOGF("[SVR][MAIN] listen UDP :%d (raw streams, MP enabled)", port);

    int ret = picoquic_packet_loop_v2(quic, &lp, loop_cb, &app);


    /* 6. 종료 시 자원 정리 */
    LOGF("[SVR][MAIN] loop end ret=%d", ret);

    rxq_close(&g_rxq);
    pthread_join(wth, NULL);

    picoquic_free(quic);
    LOGF("[SVR][MAIN] quic freed, exit ret=%d", ret);
    
    return ret;
}