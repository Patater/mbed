/*
 * Copyright (c) 2016-2018 ARM Limited
 * Copyright (c) 2020, Cypress Semiconductor Corporation. All rights reserved.
 *
 * Licensed under the Apache License Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing software
 * distributed under the License is distributed on an "AS IS" BASIS
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * \file device_definition.c
 * \brief This file defines exports the structures based on the peripheral
 * definitions from device_cfg.h.
 * This retarget file is meant to be used as a helper for baremetal
 * applications and/or as an example of how to configure the generic
 * driver structures.
 */

#include "device_definition.h"
#include "platform_base_address.h"

/* TCPWM Timer driver structures */
#if defined(CY_TCPWM0_TIMER0_S) || defined(CY_TCPWM0_TIMER1_NS)
/* Sharing the tcpwm configuration data, as the IRQ test runs in sequence */
cy_stc_tcpwm_counter_config_t tcpwm_config
    = {
    .period             = TIMER0_MATCH, /* Upper limit (wrap around) */
    .clockPrescaler     = CY_TCPWM_COUNTER_PRESCALER_DIVBY_8, /* Clk_counter = Clk_input / 8 */
    .runMode            = CY_TCPWM_COUNTER_CONTINUOUS,  /* Wrap around */
    .countDirection     = CY_TCPWM_COUNTER_COUNT_UP,
    .compareOrCapture   = CY_TCPWM_COUNTER_MODE_COMPARE,/* match compare0 */
    .compare0           = TIMER0_MATCH,
    .compare1           = 0,
    .enableCompareSwap  = false, /* swap compare0 & compare1 upon compare event */
    .interruptSources   = CY_TCPWM_INT_ON_CC,
    .captureInputMode   = CY_TCPWM_INPUT_RISINGEDGE, /* NOT used */
    .captureInput       = CY_TCPWM_INPUT_0,
    .reloadInputMode    = CY_TCPWM_INPUT_RISINGEDGE, /* NOT used */
    .reloadInput        = CY_TCPWM_INPUT_0,
    .startInputMode     = CY_TCPWM_INPUT_RISINGEDGE, /* NOT used */
    .startInput         = CY_TCPWM_INPUT_0,
    .stopInputMode      = CY_TCPWM_INPUT_RISINGEDGE, /* NOT used */
    .stopInput          = CY_TCPWM_INPUT_0,
    .countInputMode     = CY_TCPWM_INPUT_LEVEL,
    .countInput         = CY_TCPWM_INPUT_1, /* count Clk_counter */
};
#endif

#ifdef CY_TCPWM0_TIMER1_NS
tfm_timer_irq_test_dev_t CY_TCPWM0_TIMER1_DEV_NS = {
    .is_initialized     = false,
    .tcpwm_base         = TCPWM0,
    .tcpwm_counter_num  = 1,
    .timer_match_value  = TIMER1_MATCH,
    .tcpwm_config       = &tcpwm_config,
};
#endif
