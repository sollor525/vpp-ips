/*
 * ips_detection_module.c - VPP IPS Plugin Detection Engine Module Implementation
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>

#include "ips.h"
#include "ips_detection_module.h"

/**
 * @brief Initialize detection engine module
 */
clib_error_t *
ips_detection_module_init (ips_main_t * im)
{
    clib_error_t *error = 0;

    /* Initialize basic detection engine */
    error = ips_detection_init (im);
    if (error)
        return error;

    
    return 0;
}

/**
 * @brief Cleanup detection engine module
 */
void
ips_detection_module_cleanup (void)
{
    /* Detection engine cleanup */
    /* Currently no cleanup needed for basic detection */
}

/**
 * @brief Module init function
 */
static clib_error_t *
ips_detection_module_init_fn (vlib_main_t * vm)
{
    ips_main_t *im = &ips_main;
    return ips_detection_module_init (im);
}

VLIB_INIT_FUNCTION (ips_detection_module_init_fn);