/*
 * Copyright (c) 2016, ARM Limited, All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __UVISOR_API_RPC_H__
#define __UVISOR_API_RPC_H__

#include "cmsis_os.h"

#define ARRAY_COUNT(x) (sizeof(x) / sizeof(*x))

#define UVISOR_BOX_RPC_DECL(box_name, max_num_outstanding_inbound_rpc, ...) \
    const TFN_Ptr box_name##_fn_array[] = { \
        __VA_ARGS__, \
    }; \
    osMailQDef(box_name##_rpc_receive_q, max_num_outstanding_inbound_rpc, uvisor_rpc_message_t); \
    osMailQId(box_name##_rpc_receive_q_id);

#define UVISOR_BOX_RPC_HANDLE(box_name, timeout) \
    rpc_fncall_waitfor(box_name##_rpc_receive_q_id, timeout);

#define UVISOR_BOX_RPC_CALL(box_name, timeout, fn_name, p0, p1, p2, p3) \
    int result; \
    rpc_fncall(box_name##_rpc_receive_q_id, timeout, fn_name, p0, p1, p2, p3, &result); \
    return result;

#define UVISOR_BOX_RPC_INIT(box_name) \
    box_name##_rpc_receive_q_id = osMailCreate(osMailQ(box_name##_rpc_receive_q), NULL);

typedef int (*TFN_Ptr)(uint32_t, uint32_t, uint32_t, uint32_t);

/* Private for use only by uVisor lib, but the size of this type must be known
 * publicly for the UVISOR_BOX_RPC_DECL macro to work. */
struct uvisor_rpc_message_t {
    /* XXX TODO Think about what memory is accessible when and by whom. uVisor
     * has to manage moving memory around between contexts. We want to minimize
     * SVCs to uVisor, but we probably need one SVC to initiate the call (send
     * parameters to callee) and one to finish it (send back return code to
     * caller), and then there are also a bunch of RTOS SVCs. */

    /* XXX These are set by the caller, read by the callee */
    TFN_Ptr fn;
    uint32_t p0;
    uint32_t p1;
    uint32_t p2;
    uint32_t p3;

    /* The caller reads from this this queue. The callee writes to this queue.
     * */
    osMessageQId result_q_id;
};

UVISOR_EXTERN int rpc_fncall(
    osMailQId dest_mail_q_id, uint32_t timeout_ms,
    const TFN_Ptr fn, uint32_t p0, uint32_t p1, uint32_t p2, uint32_t p3,
    int *result);

UVISOR_EXTERN int rpc_fncall_waitfor(osMailQId mail_q_id, uint32_t timeout_ms);

#endif
