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

/* XXX When should this be rpc_exports.h and when should it be just rpc.h? */

#define ARRAY_COUNT(x) (sizeof(x) / sizeof(*x))

/* This is the size (in bytes) of the internal result queue type. */
#ifdef CMSIS_OS_RTX
#define RESULT_QUEUE_SIZE 38
#else
#error "Unknown how big a result queue should be for this OS"
#endif

#define UVISOR_BOX_RPC_INCOMING_QUEUE(box_name, max_num_outstanding_inbound_rpc) \
    osMailQDef(box_name##_rpc_receive_q, max_num_outstanding_inbound_rpc, uvisor_rpc_message_t); \
    osMailQId(box_name##_rpc_receive_q_id);

#define UVISOR_BOX_RPC_HANDLE(box_name, timeout) \
    rpc_fncall_waitfor(box_name##_rpc_receive_q_id, timeout);

#define UVISOR_BOX_RPC_INIT(box_name) \
    box_name##_rpc_receive_q_id = osMailCreate(osMailQ(box_name##_rpc_receive_q), NULL);

#if defined(__thumb__) && defined(__thumb2__)
/* This is chosen to be one of the explicitly undefined instructions. */
#define UVISOR_RPC_GATEWAY_MAGIC 0xA7C2F7F0
#else
#error "Unsupported instruction set. The ARM Thumb-2 instruction set must be supported."
#endif /* __thumb__ && __thumb2__ */

/* ldr r12, [pc, #<label - instr + 4>] */
#define LOAD_R12_PC_OPCODE(instr, label) \
    (uint32_t) (0xC000F8DF | ((((uint32_t) (label) - ((uint32_t) (instr) + 4)) & 0xFFF) << 16))

/* XXX TODO load directly to PC (no r12) */

/** RPC Gateway
 *
 * This macro declares an `sgw_*` function to perform a remote procedure call (RPC)
 * to the designated function. RPCs are assembled into a read-only flash
 * structure that is read and validated by uVisor before performing the
 * operation.
 *
 * @param box_name[in] The name of the source box as decalred in
 *                     `UVISOR_BOX_CONFIG`
 * @param fn_name[in]  The function being designated as an RPC target
 * @param fn_type[in]  The type of the function being designated as an RPC
 *                     target
 */
/* XXX TODO At compile time, limit the maximum number of arguments and ensure
 * that each argument is sizeof(uint32_t) in size. */
#define UVISOR_BOX_RPC_GATEWAY(box_name, fn_name, fn_type, ...) \
    static uint32_t __sgw_##fn_name(uint32_t p0, uint32_t p1, uint32_t p2, uint32_t p3) \
    { \
        /* XXX Note that p0,p1,p2,p3 may have garbage in them if not all params
         * are specified by the fn_params. */ \
        TFN_Ptr fp = (TFN_Ptr) fn_name; \
        return rpc_fncall(p0, p1, p2, p3, fp, box_name##_rpc_receive_q_id); /* XXX queue id directly used here is bad */\
    } \
    \
    /* Instanstiate the gateway. This gets resolved at link-time. */ \
    extern "C" TRPCGateway const fn_name##_rpc_gateway = { \
        .load_r12 = LOAD_R12_PC_OPCODE(__UVISOR_OFFSETOF(TRPCGateway, load_r12), \
                                       __UVISOR_OFFSETOF(TRPCGateway, function)), \
        .bx_r12   = 0x4760, /* bx r12 */ \
        .magic    = UVISOR_RPC_GATEWAY_MAGIC, \
        .box_ptr  = (uint32_t) &box_name##_cfg_ptr, \
        .function = (uint32_t) __sgw_##fn_name, \
    }; \
    \
    /* Pointer to the gateway we just created. The pointer is located in a
     * discoverable linker section. */ \
    __attribute__((section(".keep.uvisor.rpc_gateway_ptr"))) \
    static uint32_t const fn_name##_rpc_gateway_ptr = (uint32_t) &fn_name##_rpc_gateway; \
    \
    /* Declare the actual gateway. */ \
    UVISOR_EXTERN fn_type (*sgw_##fn_name)(__VA_ARGS__) __attribute__((alias(UVISOR_TO_STRING(fn_name##_rpc_gateway))));

/** RPC gateway structure
 *
 * This struct is packed because we must ensure that the `branch` field has
 * padding before itself and will be located at a valid instruction location,
 * and that the `function` field is at a pre-determined offset from the
 * `branch` field.
 */
typedef struct {
    uint32_t load_r12;
    uint16_t bx_r12;
    uint32_t magic;
    uint32_t box_ptr; /* Do we want a pointer to box config or pointer to
    queue? Probably to box config, so we can, in the future, look up RPC ACLs.
    */
    uint32_t function; /* It's like a pretend literal pool. */
} UVISOR_PACKED __attribute__((aligned(4))) TRPCGateway;

typedef uint32_t (*TFN_Ptr)(uint32_t, uint32_t, uint32_t, uint32_t);
typedef int (*TFN_RPC_Callback)(int);

/* Private for use only by uVisor lib, but the size of this type must be known
 * publicly for the UVISOR_BOX_RPC_DECL macro to work. */
typedef struct {
    /* XXX TODO Think about what memory is accessible when and by whom. uVisor
     * has to manage moving memory around between contexts. We want to minimize
     * SVCs to uVisor, but we probably need one SVC to initiate the call (send
     * parameters to callee) and one to finish it (send back return code to
     * caller), and then there are also a bunch of RTOS SVCs. */

    /* XXX These are set by the caller, read by the callee */
    uint32_t p0;
    uint32_t p1;
    uint32_t p2;
    uint32_t p3;

    TFN_Ptr fn;

    /* The caller reads from this this queue. The callee writes to this queue.
     * */
    osMessageQId result_q_id;
} uvisor_rpc_message_t;

/* This is the object to wait on for a result. */
typedef struct {
    uint8_t _internal_data[RESULT_QUEUE_SIZE];
} uvisor_rpc_result_t;

UVISOR_EXTERN uint32_t rpc_fncall(uint32_t p0, uint32_t p1, uint32_t p2, uint32_t p3,
                                  const TFN_Ptr fn, osMailQId dest_mail_q_id);

/* Return a message queue id that the caller can wait on to get a result.
 * XXX This is pure mechanism: the caller can choose to make a thread to wait
 * on result or use any thread they want whenever they feel like. We, as
 * implementers of RPC, don't make the decision for the caller. The decision is
 * best made where all the information is available to make the decision. If we
 * need to wrap that with an abstraction to make the user not have to think,
 * then we'll provide a separate wrapper to do so, but goal #1 is a stable and
 * functional API. (An API with too much policy in it is bound to be unstable,
 * as users request different policies.) */
/* Notice that we don't even need to specify any sort of timeout stuff here.
 * All that policy is decided by the user. */
UVISOR_EXTERN void rpc_fncall_async(uint32_t p0, uint32_t p1, uint32_t p2, uint32_t p3,
                                    const TFN_Ptr fn, osMailQId dest_mail_q_id,
                                    uvisor_rpc_result_t * queue);

UVISOR_EXTERN int rpc_fncall_waitfor(osMailQId mail_q_id, uint32_t timeout_ms);

/* XXX TODO Re-word this.
 * Wait for the result of a previously started asynchronous rpc. After this
 * call, ret will contain the return value of the rpc. The return value of this
 * function may indicate that there was a timeout with non-zero. */
UVISOR_EXTERN int rpc_fncall_wait(uvisor_rpc_result_t * result, uint32_t timeout_ms, uint32_t * ret);

UVISOR_EXTERN void rpc_init_result(uvisor_rpc_result_t * queue);

#endif
