#ifndef DEFAULT_HEADER_H
#define DEFAULT_HEADER_H

/* [시스템 표준 헤더] */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>
#include <pthread.h>

/* [네트워크 관련 시스템 헤더] */
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

/* [picoquic 라이브러리 헤더] */
#include "picoquic.h"
#include "picoquic_utils.h"
#include "picoquic_packet_loop.h"
#include "picoquic_internal.h"
#include "qlog.h"
#include "picoquic_binlog.h"
#include "autoqlog.h"

/* [외부 모듈 헤더] */
#include "camera.h"

#endif