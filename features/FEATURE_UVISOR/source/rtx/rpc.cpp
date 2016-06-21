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

#include "uvisor-lib/uvisor-lib.h"

UVISOR_EXTERN int rpc_fncall(
    osMailQId dest_mail_q_id, uint32_t timeout_ms,
    const TFN_Ptr fn, uint32_t p0, uint32_t p1, uint32_t p2, uint32_t p3,
    int *result)
{
    /* Note: This runs in caller context. */

    /* TODO - check the type of the call target.
            - move this function to uvisor lib.
            - if call target is not a known RPC target, do a normal local
              function call. (async will have to use the queue still, perhaps)
            - variadic function
            - uVisor firewall
            - target queue from lib config
    */

    uvisor_rpc_message_t * msg;
    osEvent event;

    /* Make a queue of size 1 to receive the result into. XXX Only the target
     * function's box context should be allowed to post to this. But, that's
     * not good enough. That target box is not really trusted, yet we need to
     * trust that it will eventually set a return code, not give us back too
     * many return codes, and the wrong not set nonsense return codes; some
     * other task in the target box could be writing to all queue ids (32-bit
     * easy to brute force) in a loop nonsense return codes: if one doesn't
     * call into that box, they don't have a problem. But, when they do, they
     * have to have some sort of trust in how the return codes get posted back.
     * */
    osMessageQDef(result_q, 1, int);
    osMessageQId(result_q_id);
    result_q_id = osMessageCreate(osMessageQ(result_q), NULL);

    /* XXX The pool for the should be in box private memory, so this needs
     * some rework. uVisor needs to do the data copy on behalf of the sender if
     * the firewall rules pass for this caller. */
    /* TODO obtain the queue to use from the libconfig, after having looked up
     * the target and found it to be a valid RPC target. */
    /* XXX Not sure if we want to wait forever on the destination queue to have
     * room. I think we do, as it's the waiting for the result return value
     * that the user specified a timeout for. However, we might not want to
     * wait forever in all cases. Maybe this should be 0 timeout instead. */
    msg = (uvisor_rpc_message_t *) osMailAlloc(dest_mail_q_id, osWaitForever);
    msg->fn = fn;
    msg->p0 = p0;
    msg->p1 = p1;
    msg->p2 = p2;
    msg->p3 = p3;
    msg->result_q_id = result_q_id;

    /* XXX Why did we want to have send queues within the caller process for
     * RPC? Maybe because this function wouldn't be able to use the receive
     * queue in the callee process directly. For now, this is ok because
     * prototyping. After we add uVisor firewall, of course we can't use the
     * queue directly. */
    osMailPut(dest_mail_q_id, msg);

    /* Wait for the function to return. In the asynchronous case, we'd not wait
     * like this, but instead perhaps have a thread (for callback context) wait
     * and then call the callback when semaphore is ready. */
    event = osMessageGet(result_q_id, timeout_ms);
    if (event.status == osEventMessage)
    {
        *result = (int) event.value.p;
        osMessageCreate(osMessageQ(result_q), NULL);
        return 0;
    }

    /* No message was available. Probably timed out. */
    return -1;
}

UVISOR_EXTERN int rpc_fncall_waitfor(osMailQId mail_q_id, uint32_t timeout_ms)
{
    /* Note: This runs in callee context. */

    osEvent event;
    uvisor_rpc_message_t * msg;

    /* XXX We aren't smartly waiting only for those functions specified in the
     * array, but for any inbound RPC. This should be thought through better.
     * As currently implemented, we completely ignore the fn_ptr_array and the
     * fn_count. uVisor will not enqueue RPC messages that we didn't declare as
     * valid RPC targets, so there is no need for additional checks here to
     * make sure the function is in our list; but this also assumes that there
     * is only one call to rpc_fncall_waitfor in a process, or that all calls
     * to rpc_fncall_waitfor use the same function list. If we want to be
     * smarter and only wake up if the fncall_waitfor, we may have to create
     * a queue per RPC target function; but I don't think RTX can wait on
     * multiple queues right now (that'd have to be serial); RTX can wait for
     * multiple events, but there are only 32 available and it'd suck to burn
     * through them for implementing uVisor RPC. Anyway, think this stuff
     * through more later. */

    /* This scheduling algorithm is dumb for now. We only process up to 1 RPC
     * at a time, even if more are outstanding. Call rpc_fncall_waitfor
     * multiple times if you want to process multiple RPC messages. There is
     * also no parallel dispatching to multiple threads. */
    event = osMailGet(mail_q_id, timeout_ms);
    if (event.status == osEventMail)
    {
        int result;
        osStatus status;

        msg = (uvisor_rpc_message_t *) event.value.p;

        /* Note that the uVisor_RPC_Message is placed by uVisor into this
         * queue. Nobody else is allow to put stuff into the queue. So, we can
         * assume the queue things are good and can just dispatch now. (no need
         * to check msg->fn for non-NULL). TODO prevent others from enqueueing
         * into the rpc queue (uVisor queue firewall). One idea to do this is
         * to make the queue in box-private memory, and to only if the firewall
         * passes, depriv to target box context to enqueue the item and return.
         * This is a lot of overhead, but we can optimize that out later (by
         * perhaps a privileged mode handler provided by RTX to uVisor that can
         * enqueue items) */

        /* Dispatch the RPC. */
        result = msg->fn(msg->p0, msg->p1, msg->p2, msg->p3); /*
        Not sure we need this 4 register sort of interface for target RPC
        functions. A single void * argument should work just fine, but doesn't
        allow clients freedom over calling convention (maybe they want more
        stuff passed by registers than a single void * would allow, for some
        reason). */

        /* Notify the caller. Don't wait for any room in the caller's queue;
         * fail to post the return value if the caller's queue has trouble. */
        static const uint32_t result_timeout_ms = 0;
        status = osMessagePut(msg->result_q_id, result, result_timeout_ms);
        (void)status; /* Ignore result, since we don't care about the caller's
                         result queue being broken. */

        /* Now that the function has returned, free the item. It is good that
         * the caller doesn't have to trust that the callee will do this.
         * uVisor lib does it for the caller. uVisor lib has to be trusted...
         * */
        osMailFree(mail_q_id, msg);
        return 0;
    }

    return event.status;
}
