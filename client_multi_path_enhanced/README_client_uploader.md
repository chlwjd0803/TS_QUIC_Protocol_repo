# Client Uploader (`client_uploader.c`) 파라미터 가이드

이 문서는 `client_uploader.c` 소스 코드의 **주요 함수와 매개변수(인자)** 역할을 직관적으로 파악하기 위한 문서입니다.
이 프로그램은 카메라 영상을 캡처하여 **멀티패스(Wi-Fi + Hotspot)** 환경에서 최적의 경로를 선택해 서버로 전송합니다.

---

## 1. 프로그램 실행 옵션 (Main Arguments)
터미널에서 클라이언트를 실행할 때 입력하는 값들입니다. (`main` 함수)

| 순서 | 매개변수 명 | 예시 값 | 설명 (역할) |
|---|---|---|---|
| 1 | `server_ip` | `192.168.0.83` | 데이터를 보낼 **서버 IP 주소** |
| 2 | `local_alt_ip` | `192.168.0.170` | 보조 네트워크(Hotspot/LTE)의 로컬 IP 주소 |
| 3 | `port` | `4433` | 서버 포트 번호 |
| 4 | `local_usb_ip` | `192.168.0.50` | 주 네트워크(Wi-Fi)의 로컬 IP 주소 |

> **참고:** 이 IP 주소들은 경로 선택 로직에서 어떤 경로가 Wi-Fi이고 어떤 경로가 핫스팟인지 구분하는 식별자로 사용됩니다. 현재 코드에서 보조 네트워크가 Wi-Fi 사설 IP주소로 확인되어, 주 네트워크와 보조 네트워크가 반드시 Wi-Fi, 셀룰러로 고정되어있지 않는 것으로 추정됩니다.

---

## 2. 경로 선택 핵심 로직 (Path Selection)
두 개의 네트워크 경로 중 어디로 보낼지 결정하는 함수들입니다.

### pick_primary_idx
**기능:** 현재 네트워크 상태(RTT, 손실률)를 분석하여, Wi-Fi와 핫스팟 중 데이터를 보낼 주 경로(Primary)의 번호를 반환합니다.

> int pick_primary_idx(picoquic_cnx_t* c, pathsel_t* sel, int sc, uint32_t ip_wlan_be, uint32_t ip_usb_be, int* last_primary, uint64_t now, uint64_t* last_switch_time)

| 매개변수 | 설명 |
|---|---|
| **c** | **[연결 정보]** 현재 QUIC 연결 객체 |
| **sel** | **[후보 목록]** 현재 사용 가능한 경로(Path)들의 리스트 |
| **sc** | **[개수]** 후보 경로의 개수 |
| **ip_wlan_be** | **[Wi-Fi 식별자]** Wi-Fi 인터페이스의 IP 주소 (어떤 게 Wi-Fi인지 찾기 위함) |
| **ip_usb_be** | **[USB 식별자]** 핫스팟/USB 테더링 인터페이스의 IP 주소 |
| **last_primary** | **[이전 상태]** 방금 전까지 사용하던 경로 번호 (빈번한 교체 방지용) |
| **now** | **[현재 시간]** 경로 교체 쿨타임 계산용 |
| **last_switch_time** | **[마지막 교체 시간]** 가장 최근에 경로를 바꾼 시간 |

### compute_metric_safe
**기능:** 특정 경로의 품질 점수(등급)를 매깁니다.

> path_metric_t compute_metric_safe(picoquic_path_t* p)

| 매개변수 | 설명 |
|---|---|
| **p** | **[대상 경로]** 품질을 검사할 경로 객체 |
| **반환값** | **[성적표]** `grade`(0:좋음, 1:보통, 2:나쁨), `rtt_ms`(지연시간), `loss_rate`(손실률)가 담긴 구조체 |

### fsm_pick
**기능:** 계산된 점수를 바탕으로 실제 스위칭(전환) 여부를 결정하는 의사결정 함수입니다.

> int fsm_pick(const path_metric_t* WLAN, const path_metric_t* USB, ..., int* last_primary, ...)

| 매개변수 | 설명 |
|---|---|
| **WLAN / USB** | **[성적표]** 위에서 계산한 Wi-Fi와 USB 경로의 품질 점수 |
| **last_primary** | **[현재 상태]** 지금 쓰고 있는 경로 |
| **반환값** | **[최종 결정]** 다음 패킷을 보낼 경로의 ID |

---

## 3. 전송 및 루프 (Transmission Loop)

### loop_cb
**기능:** 프로그램의 심장부입니다. 주기적으로 깨어나서 **카메라 프레임을 가져오고 -> 경로를 선택하고 -> 전송**합니다.

> int loop_cb(picoquic_quic_t* quic, picoquic_packet_loop_cb_enum cb_mode, void* cb_ctx, void* callback_return)

| 매개변수 | 설명 |
|---|---|
| **quic** | **[QUIC 엔진]** 전체 라이브러리 상태 |
| **cb_mode** | **[호출 시점]** 루프 상태 (송신 후, 수신 후, 타이머 등) |
| **cb_ctx** | **[전역 상태]** `main`에서 만든 `tx_t` 구조체 (모든 데이터를 담고 있음) |

### send_on_path_safe
**기능:** 지정된 경로(Path)로 데이터를 강제로 보냅니다. (QUIC은 원래 경로를 알아서 잡지만, 여기서는 우리가 강제 지정함)

> int send_on_path_safe(picoquic_cnx_t* c, tx_t* st, int k, const uint8_t* hdr, size_t hlen, const uint8_t* payload, size_t plen)

| 매개변수 | 설명 |
|---|---|
| **c** | **[연결 정보]** 연결 객체 |
| **st** | **[전역 상태]** 스트림 ID 관리용 |
| **k** | **[목표 경로]** 데이터를 태워 보낼 경로의 인덱스 번호 (0, 1, 2...) |
| **hdr / hlen** | **[헤더]** 보낼 데이터의 헤더 부분(길이 정보)과 그 크기 |
| **payload / plen** | **[본문]** 실제 영상 데이터와 그 크기 |

---

## 4. 카메라 및 유틸리티 (Hardware & Utils)

### camera_thread_main
**기능:** 네트워크 전송과 별개로 계속 돌면서 카메라 영상을 찍어 메모리에 저장해두는 스레드 함수입니다.

> void* camera_thread_main(void* arg)

| 매개변수 | 설명 |
|---|---|
| **arg** | **[전역 상태]** `tx_t` 구조체. 찍은 사진을 저장할 버퍼 주소를 알기 위해 필요합니다. |

### make_bound_socket
**기능:** 특정 네트워크 카드(NIC)를 강제로 사용하기 위해 소켓을 특정 IP에 묶습니다(Binding).

> int make_bound_socket(const char* ip, int port)

| 매개변수 | 설명 |
|---|---|
| **ip** | **[로컬 IP]** 사용할 네트워크 카드의 IP (예: Wi-Fi IP) |
| **port** | **[포트]** 사용할 로컬 포트 번호 |

---

## 5. 주요 구조체 상세 (Data Structures)
함수 인자로 계속 전달되는 `tx_t` 구조체의 내부입니다.

### tx_t (전송기 상태 관리자)
프로그램 전체의 상태를 저장하는 거대한 구조체입니다. `st` 또는 `ctx`라는 이름으로 전달됩니다.

| 멤버 변수 | 설명 |
|---|---|
| **cnx** | 현재 서버와의 연결 상태 포인터 |
| **cam / cam_buf** | 카메라 장치 핸들 및 캡처된 이미지가 저장되는 메모리 공간 |
| **cam_len / cam_seq** | 가장 최근에 찍힌 이미지의 크기와 번호 |
| **ip_wlan_be / ip_usb_be** | Wi-Fi와 USB 테더링을 구분하기 위한 IP 주소값 (바이너리 형태) |
| **sid_per_path[]** | 각 경로마다 전용으로 쓰기 위해 할당된 스트림 ID 목록 |
| **last_primary_idx** | 직전에 데이터를 보냈던 경로 번호 (핑퐁 방지용) |
| **b[MAX_PATHS]** | 각 경로가 사용 가능한지(Ready) 체크하는 플래그 배열 |