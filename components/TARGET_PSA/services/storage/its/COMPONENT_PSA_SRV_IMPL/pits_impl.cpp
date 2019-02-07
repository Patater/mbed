/* Copyright (c) 2018 ARM Limited
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

#include <cstring>
#include "KVMap.h"
#include "KVStore.h"
#include "TDBStore.h"
#include "psa/internal_trusted_storage.h"
#include "psa_storage_common_impl.h"
#include "pits_impl.h"
#include "mbed_error.h"
#include "mbed_toolchain.h"

using namespace mbed;

#ifdef   __cplusplus
extern "C"
{
#endif

#define STR_EXPAND(tok)                 #tok
#define ITS_VERSION_KEY "PSA_ITS_VERSION"  // ITS version entry identifier in TDBStore

static KVStore *kvstore = NULL;

MBED_WEAK psa_status_t its_version_migrate(KVStore *kvstore,
                                           const psa_storage_version_t *old_version, const psa_storage_version_t *new_version)
{
    (void)kvstore;
    (void)old_version;
    (void)new_version;
    return PSA_SUCCESS;
}


static void its_init(void)
{
    KVMap &kv_map = KVMap::get_instance();
    psa_storage_version_t version = {PSA_ITS_API_VERSION_MAJOR, PSA_ITS_API_VERSION_MINOR};
    kvstore = kv_map.get_internal_kv_instance(STR_EXPAND(MBED_CONF_STORAGE_DEFAULT_KV));
    if (!kvstore) {
        // Can only happen due to system misconfiguration.
        // Thus considered as unrecoverable error for runtime.
        error("Failed getting kvstore instance\n");
    }

    psa_storage_handle_version(kvstore, ITS_VERSION_KEY, &version, its_version_migrate);
}

// used from test only
void its_deinit(void)
{
    kvstore = NULL;
}


psa_status_t psa_its_set_impl(int32_t pid, psa_storage_uid_t uid, uint32_t data_length, const void *p_data, psa_storage_create_flags_t create_flags)
{
    if (!kvstore) {
        its_init();
    }

    return psa_storage_set_impl(kvstore, pid, uid, data_length, p_data, create_flags);
}

psa_status_t psa_its_get_impl(int32_t pid, psa_storage_uid_t uid, uint32_t data_offset, uint32_t data_length, void *p_data)
{
    if (!kvstore) {
        its_init();
    }

    return psa_storage_get_impl(kvstore, pid, uid, data_offset, data_length, p_data);
}

psa_status_t psa_its_get_info_impl(int32_t pid, psa_storage_uid_t uid, struct psa_storage_info_t *p_info)
{
    if (!kvstore) {
        its_init();
    }

    return psa_storage_get_info_impl(kvstore, pid, uid, p_info);
}

psa_status_t psa_its_remove_impl(int32_t pid, psa_storage_uid_t uid)
{
    if (!kvstore) {
        its_init();
    }

    return psa_storage_remove_impl(kvstore, pid, uid);
}

psa_status_t psa_its_reset_impl()
{
    // Do not call its_init here to avoid version check before reset
    KVMap &kv_map = KVMap::get_instance();
    kvstore = kv_map.get_internal_kv_instance(STR_EXPAND(MBED_CONF_STORAGE_DEFAULT_KV));
    if (!kvstore) {
        // Can only happen due to system misconfiguration.
        // Thus considered as unrecoverable error for runtime.
        error("Failed getting kvstore instance\n");
    }

    return psa_storage_reset_impl(kvstore);
}

#ifdef   __cplusplus
}
#endif
