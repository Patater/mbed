/*
 * Copyright (c) 2018-2020 Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "crypto.h"
#include "default_random_seed.h"
#include "psa/internal_trusted_storage.h"

int mbed_default_seed_read(unsigned char *buf, size_t buf_len)
{
    size_t actual_size;
    psa_status_t rc = psa_its_get(PSA_CRYPTO_ITS_RANDOM_SEED_UID, 0, buf_len, buf, &actual_size);
    return ( rc );
}

int mbed_default_seed_write(unsigned char *buf, size_t buf_len)
{
    psa_status_t rc = psa_its_set(PSA_CRYPTO_ITS_RANDOM_SEED_UID, buf_len, buf, 0);
    return ( rc );
}

