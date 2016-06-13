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
#ifndef __UVISOR_API_EVIL_BACKDOOR_H__
#define __UVISOR_API_EVIL_BACKDOOR_H__

#include "api/inc/uvisor_exports.h"
#include <stdint.h>

UVISOR_EXTERN void uvisor_evil_backdoor_write  (uint32_t addr, uint32_t value, uint8_t bytes);
UVISOR_EXTERN void uvisor_evil_backdoor_write8 (uint32_t addr, uint8_t  value);
UVISOR_EXTERN void uvisor_evil_backdoor_write16(uint32_t addr, uint16_t value);
UVISOR_EXTERN void uvisor_evil_backdoor_write32(uint32_t addr, uint32_t value);

UVISOR_EXTERN uint32_t uvisor_evil_backdoor_read  (uint32_t addr, uint8_t bytes);
UVISOR_EXTERN uint8_t  uvisor_evil_backdoor_read8 (uint32_t addr);
UVISOR_EXTERN uint16_t uvisor_evil_backdoor_read16(uint32_t addr);
UVISOR_EXTERN uint32_t uvisor_evil_backdoor_read32(uint32_t addr);


#endif /* __UVISOR_API_EVIL_BACKDOOR_H__ */
