/*
 * ips_timer_api.c - VPP IPS Timer API Implementation
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

#include "ips.h"
#include "session/ips_session_timer.h"

/* Timer management API definitions */
/*
 * TODO: Timer API functions temporarily disabled
 * These functions need proper API type definitions from the API generator
 * For now, the core timer functionality is provided by the session module
 */

/**
 * @brief Initialize timer API
 */
void
ips_timer_api_init (vlib_main_t * vm)
{
    /* Timer API initialization */
    /* Currently no API functions are implemented */
}

/**
 * @brief Cleanup timer API
 */
void
ips_timer_api_cleanup (vlib_main_t * vm)
{
    /* Timer API cleanup */
    /* Currently no API functions are implemented */
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */