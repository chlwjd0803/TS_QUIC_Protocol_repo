#ifndef PATH_ALGO_H
#define PATH_ALGO_H

#include "picoquic.h"
#include "struct_type.h"
#include "net_tools.h"
#include "quic_helpers.h"

/**
 * @brief 현재는 싱글 패스 모드이므로 복잡한 선택 로직은 제거되었습니다.
 * 필요 시 검증된 경로가 있는지 확인하는 용도로만 사용합니다.
 */

static inline int is_path0_verified(picoquic_cnx_t* c)
{
    if (c && c->nb_paths > 0 && c->path[0] && c->path[0]->first_tuple) {
        return c->path[0]->first_tuple->challenge_verified;
    }
    return 0;
}

#endif