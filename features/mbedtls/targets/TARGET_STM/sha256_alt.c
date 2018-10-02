/*
 *  sha256_alt.c for SHA256 HASH
 *******************************************************************************
 * Copyright (c) 2017, STMicroelectronics
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
#include "mbedtls/sha256.h"

#if defined(MBEDTLS_SHA256_ALT)
#include "mbedtls/platform.h"

#include "cmsis_os.h"

osMutexDef(SHA256Mutex);
osMutexId sha256_mutex_id;

/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize(void *v, size_t n)
{
    volatile unsigned char *p = v;
    while (n--) {
        *p++ = 0;
    }
}

static int st_sha256_restore_hw_context(mbedtls_sha256_context *ctx)
{
    printf(">\tt%p %p %s\n", osThreadGetId(), ctx, __FUNCTION__);
    if (!ctx->init)
    {
        /* Fail */
        printf("<\t%p:%s %d\n", osThreadGetId(), __FUNCTION__, 0);
        return 0;
    }
    uint32_t i;
    uint32_t tickstart;
    /* allow multi-instance of HASH use: save context for HASH HW module CR */
    /* Check that there is no HASH activity on going */
    tickstart = HAL_GetTick();
    while ((HASH->SR & (HASH_FLAG_BUSY | HASH_FLAG_DMAS)) != 0) {
        if ((HAL_GetTick() - tickstart) > ST_SHA256_TIMEOUT) {
            printf("<\trestore timeout: HASH processor is busy\n");
            printf("<\t%p:%s %d\n", osThreadGetId(), __FUNCTION__, 0);
            return 0; // timeout: HASH processor is busy
        }
    }
    HASH->STR = ctx->ctx_save_str;
    HASH->CR = (ctx->ctx_save_cr | HASH_CR_INIT);
    for (i = 0; i < 38; i++) {
        HASH->CSR[i] = ctx->ctx_save_csr[i];
    }
    printf("<\t%p:%s %d\n", osThreadGetId(), __FUNCTION__, 1);
    return 1;
}

static int st_sha256_save_hw_context(mbedtls_sha256_context *ctx)
{
    printf(">\t%p:%s %p\n", osThreadGetId(), __FUNCTION__, ctx);
    if (!ctx->init)
    {
        /* Fail */
        printf("<\t%p:%s %d\n", osThreadGetId(), __FUNCTION__, 0);
        return 0;
    }
    uint32_t i;
    uint32_t tickstart;
    /* Check that there is no HASH activity on going */
    tickstart = HAL_GetTick();
    while ((HASH->SR & (HASH_FLAG_BUSY | HASH_FLAG_DMAS)) != 0) {
        if ((HAL_GetTick() - tickstart) > ST_SHA256_TIMEOUT) {
            printf("<\tsave timeout: HASH processor is busy\n");
            printf("<\t%p:%s %d\n", osThreadGetId(), __FUNCTION__, 0);
            return 0; // timeout: HASH processor is busy
        }
    }
    /* allow multi-instance of HASH use: restore context for HASH HW module CR */
    ctx->ctx_save_cr = HASH->CR;
    ctx->ctx_save_str = HASH->STR;
    for (i = 0; i < 38; i++) {
        ctx->ctx_save_csr[i] = HASH->CSR[i];
    }
    printf("<\t%p:%s %d\n", osThreadGetId(), __FUNCTION__, 1);
    return 1;
}

void mbedtls_sha256_init(mbedtls_sha256_context *ctx)
{
    printf(">t:%p ctx:%p %s\n", osThreadGetId(), ctx, __FUNCTION__);
    printf("CCC %s( &ctx_%p );\n", __FUNCTION__, ctx);
    mbedtls_zeroize(ctx, sizeof(mbedtls_sha256_context));

    sha256_mutex_id = osMutexCreate(osMutex(SHA256Mutex));
    if (sha256_mutex_id == NULL) {
        printf("Failed to make mutex\n");
    }

    /* Enable HASH clock */
    __HAL_RCC_HASH_CLK_ENABLE();

    ctx->init = 1;
    printf("<%p:%s\n", osThreadGetId(), __FUNCTION__);
}

void mbedtls_sha256_free(mbedtls_sha256_context *ctx)
{
    printf(">t:%p ctx:%p %s\n", osThreadGetId(), ctx, __FUNCTION__);
    printf("CCC %s( &ctx_%p );\n", __FUNCTION__, ctx);
    if (ctx == NULL) {
        return;
    }
    if (!ctx->init) {
        /* double free */
        printf("Double free\n");
    }
    mbedtls_zeroize(ctx, sizeof(mbedtls_sha256_context));
    ctx->init = 0;
    printf("<%p:%s\n", osThreadGetId(), __FUNCTION__);
}

void mbedtls_sha256_clone(mbedtls_sha256_context *dst,
                          const mbedtls_sha256_context *src)
{
    printf(">t:%p %s src:%p->dst:%p\n", osThreadGetId(), __FUNCTION__, src, dst);
    printf("CCC %s( &ctx_%p, &ctx_%p );\n", __FUNCTION__, dst, src);
    *dst = *src;
    printf("<%p:%s\n", osThreadGetId(), __FUNCTION__);
}

int mbedtls_sha256_starts_ret(mbedtls_sha256_context *ctx, int is224)
{
    int err;
    printf(">t:%p ctx:%p %s is224:%d\n", osThreadGetId(), ctx, __FUNCTION__, is224);
    printf("CCC %s( &ctx_%p, %d );\n", __FUNCTION__, ctx, is224);
    if (!ctx->init)
    {
        printf("fail: use without init\n");
        err = MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
        goto fail;
    }
    osStatus status = osMutexWait(sha256_mutex_id, 0); /* XXX mutex should be in the context... */
    if (status != osOK) {
        printf("concurrent operation not supported\n");
        err = MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
        goto fail;
    }

    /* HASH IP initialization */
    if (HAL_HASH_DeInit(&ctx->hhash_sha256) == HAL_ERROR) {
        err = MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
        goto fail;
    }

    ctx->is224 = is224;
    /* HASH Configuration */
    ctx->hhash_sha256.Init.DataType = HASH_DATATYPE_8B;
    /* clear CR ALGO value */
    HASH->CR &= ~HASH_CR_ALGO_Msk;
    if (HAL_HASH_Init(&ctx->hhash_sha256) == HAL_ERROR) {
        // error found to be returned
        err = MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
        goto fail;
    }
    if (st_sha256_save_hw_context(ctx) != 1) {
        // return HASH_BUSY timeout Error here
        err = MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
        goto fail;
    }

    status = osMutexRelease(sha256_mutex_id);
    if (status != osOK) {
        printf("failed to release mutex\n");
        printf("<%p:%s %d\n", osThreadGetId(), __FUNCTION__, MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED);
        return MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
    }

    printf("<%p:%s %d\n", osThreadGetId(), __FUNCTION__, 0);
    return 0;
fail:
    status = osMutexRelease(sha256_mutex_id);
    if (status != osOK) {
        printf("failed to release mutex\n");
        printf("<%p:%s %d\n", osThreadGetId(), __FUNCTION__, MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED);
        return MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
    }
    printf("<%p:%s %d\n", osThreadGetId(), __FUNCTION__, err);
    return err;
}

int mbedtls_internal_sha256_process(mbedtls_sha256_context *ctx, const unsigned char data[ST_SHA256_BLOCK_SIZE])
{
    int err;
    printf(">\t%p ctx:%p %s\n", osThreadGetId(), ctx, __FUNCTION__);
    if (!ctx->init)
    {
        printf("<\tfail: use without init\n");
        err = MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
        printf("<\t%p:%s %d\n", osThreadGetId(), __FUNCTION__, err);
        return err;
    }
    if (st_sha256_restore_hw_context(ctx) != 1) {
        // Return HASH_BUSY timeout error here
        return MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
    }
    if (ctx->is224 == 0) {
        if (HAL_HASHEx_SHA256_Accumulate(&ctx->hhash_sha256, (uint8_t *) data, ST_SHA256_BLOCK_SIZE) != 0) {
            printf("<\t%p:%s %d\n", osThreadGetId(), __FUNCTION__, MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED);
            return MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
        }
    } else {
        if (HAL_HASHEx_SHA224_Accumulate(&ctx->hhash_sha256, (uint8_t *) data, ST_SHA256_BLOCK_SIZE) != 0) {
            printf("<\t%p:%s %d\n", osThreadGetId(), __FUNCTION__, MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED);
            return MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
        }
    }

    if (st_sha256_save_hw_context(ctx) != 1) {
        // Return HASH_BUSY timeout error here
        printf("<\t%p:%s %d\n", osThreadGetId(), __FUNCTION__, MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED);
        return MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
    }

    printf("<\t%p:%s %d\n", osThreadGetId(), __FUNCTION__, 0);
    return 0;
}

int mbedtls_sha256_update_ret(mbedtls_sha256_context *ctx, const unsigned char *input, size_t ilen)
{
    int err;
    size_t currentlen = ilen;

    printf(">t:%p ctx:%p %s ilen:%zu\n", osThreadGetId(), ctx, __FUNCTION__, ilen);
    printf("CCC %s( &ctx_%p, XXXinput, %zu );\n", __FUNCTION__, ctx, ilen);

    if (!ctx->init)
    {
        printf("fail: use without init\n");
        err = MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
        printf("<%p:%s %d\n", osThreadGetId(), __FUNCTION__, err);
        return err;
    }

    osStatus status = osMutexWait(sha256_mutex_id, 0);
    if (status != osOK) {
        printf("concurrent operation not supported\n");
        err = MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
        goto fail;
    }

    if (st_sha256_restore_hw_context(ctx) != 1) {
        // Return HASH_BUSY timeout error here
        err = MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
        goto fail;
    }

    // store mechanism to accumulate ST_SHA256_BLOCK_SIZE bytes (512 bits) in the HW
    if (currentlen == 0) { // only change HW status is size if 0
        if (ctx->hhash_sha256.Phase == HAL_HASH_PHASE_READY) {
            /* Select the SHA256 or SHA224 mode and reset the HASH processor core, so that the HASH will be ready to compute
             the message digest of a new message */
            if (ctx->is224 == 0) {
                HASH->CR |= HASH_ALGOSELECTION_SHA256 | HASH_CR_INIT;
            } else {
                HASH->CR |= HASH_ALGOSELECTION_SHA224 | HASH_CR_INIT;
            }
        }
        ctx->hhash_sha256.Phase = HAL_HASH_PHASE_PROCESS;
    } else if (currentlen < (ST_SHA256_BLOCK_SIZE - ctx->sbuf_len)) {
        // only buffurize
        memcpy(ctx->sbuf + ctx->sbuf_len, input, currentlen);
        ctx->sbuf_len += currentlen;
    } else {
        // fill buffer and process it
        memcpy(ctx->sbuf + ctx->sbuf_len, input, (ST_SHA256_BLOCK_SIZE - ctx->sbuf_len));
        currentlen -= (ST_SHA256_BLOCK_SIZE - ctx->sbuf_len);
        err = mbedtls_internal_sha256_process(ctx, ctx->sbuf);
        if (err != 0) {
            goto fail;
        }
        // Process every input as long as it is %64 bytes, ie 512 bits
        size_t iter = currentlen / ST_SHA256_BLOCK_SIZE;
        if (iter != 0) {
            if (ctx->is224 == 0) {
                if (HAL_HASHEx_SHA256_Accumulate(&ctx->hhash_sha256, (uint8_t *)(input + ST_SHA256_BLOCK_SIZE - ctx->sbuf_len), (iter * ST_SHA256_BLOCK_SIZE)) != 0) {
                    err = MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
                    goto fail;
                }
            } else {
                if (HAL_HASHEx_SHA224_Accumulate(&ctx->hhash_sha256, (uint8_t *)(input + ST_SHA256_BLOCK_SIZE - ctx->sbuf_len), (iter * ST_SHA256_BLOCK_SIZE)) != 0) {
                    err = MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
                    goto fail;
                }
            }
        }
        // sbuf is completely accumulated, now copy up to 63 remaining bytes
        ctx->sbuf_len = currentlen % ST_SHA256_BLOCK_SIZE;
        if (ctx->sbuf_len != 0) {
            memcpy(ctx->sbuf, input + ilen - ctx->sbuf_len, ctx->sbuf_len);
        }
    }
    if (st_sha256_save_hw_context(ctx) != 1) {
        // Return HASH_BUSY timeout error here
        err = MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
        goto fail;
    }

    status = osMutexRelease(sha256_mutex_id);
    if (status != osOK) {
        printf("failed to release mutex\n");
        printf("<%p:%s %d\n", osThreadGetId(), __FUNCTION__, MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED);
        return MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
    }

    printf("<%p:%s %d\n", osThreadGetId(), __FUNCTION__, 0);
    return 0;
fail:
    status = osMutexRelease(sha256_mutex_id);
    if (status != osOK) {
        printf("failed to release mutex\n");
        printf("<%p:%s %d\n", osThreadGetId(), __FUNCTION__, MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED);
        return MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
    }

    printf("<%p:%s %d\n", osThreadGetId(), __FUNCTION__, err);
    return err;
}

int mbedtls_sha256_finish_ret(mbedtls_sha256_context *ctx, unsigned char output[32])
{
    printf(">t:%p ctx:%p %s\n", osThreadGetId(), ctx, __FUNCTION__);
    printf("CCC %s( &ctx_%p, XXXoutput );\n", __FUNCTION__, ctx);
    int err;
    if (!ctx->init)
    {
        printf("fail: use without init\n");
        err = MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
        printf("<%p:%s %d\n", osThreadGetId(), __FUNCTION__, err);
        return err;
    }
    osStatus status = osMutexWait(sha256_mutex_id, 0);
    if (status != osOK) {
        printf("concurrent operation not supported\n");
        printf("<%p:%s %d\n", osThreadGetId(), __FUNCTION__, MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED);
        return MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
    }

    if (st_sha256_restore_hw_context(ctx) != 1) {
        // Return HASH_BUSY timeout error here
        err = MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
        goto fail;
    }
    /* Last accumulation for extra bytes in sbuf_len */
    /* This allows the HW flags to be in place in case mbedtls_sha256_update has not been called yet */
    if (ctx->is224 == 0) {
        if (HAL_HASHEx_SHA256_Accumulate(&ctx->hhash_sha256, ctx->sbuf, ctx->sbuf_len) != 0) {
            err = MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
            goto fail;
        }
    } else {
        if (HAL_HASHEx_SHA224_Accumulate(&ctx->hhash_sha256, ctx->sbuf, ctx->sbuf_len) != 0) {
            err = MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
            goto fail;
        }
    }

    mbedtls_zeroize(ctx->sbuf, ST_SHA256_BLOCK_SIZE);
    ctx->sbuf_len = 0;
    __HAL_HASH_START_DIGEST();

    if (ctx->is224 == 0) {
        if (HAL_HASHEx_SHA256_Finish(&ctx->hhash_sha256, output, 10) != 0) {
            err = MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
            goto fail;
        }
    } else {
        if (HAL_HASHEx_SHA224_Finish(&ctx->hhash_sha256, output, 10) != 0) {
            err = MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
            goto fail;
        }
    }
    if (st_sha256_save_hw_context(ctx) != 1) {
        // Return HASH_BUSY timeout error here
        err = MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
        goto fail;
    }

    status = osMutexRelease(sha256_mutex_id);
    if (status != osOK) {
        printf("failed to release mutex\n");
        printf("<%p:%s %d\n", osThreadGetId(), __FUNCTION__, MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED);
        return MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
    }

    printf("<%p:%s %d\n", osThreadGetId(), __FUNCTION__, 0);
    return 0;
fail:
    status = osMutexRelease(sha256_mutex_id);
    if (status != osOK) {
        printf("failed to release mutex\n");
        printf("<%p:%s %d\n", osThreadGetId(), __FUNCTION__, MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED);
        return MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
    }
    printf("<%p:%s %d\n", osThreadGetId(), __FUNCTION__, err);
    return err;
}

#endif /*MBEDTLS_SHA256_ALT*/
