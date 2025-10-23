/*
 * ips_rules_module.c - VPP IPS Plugin Rules Module Implementation
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
#include <sys/stat.h>

#include "ips.h"
#include "ips_rules_module.h"

/**
 * @brief Initialize rules module
 */
clib_error_t *
ips_rules_module_init (void)
{
    /* Initialize rule parser */
    /* TODO: Re-enable when rule parser is implemented */
    /*
    int result = ips_rule_parser_init ();
    if (result != 0)
        return clib_error_return (0, "Failed to initialize rule parser");
    */

    return 0;
}

/**
 * @brief Cleanup rules module
 */
void
ips_rules_module_cleanup (void)
{
    /* Clear all rules */
    ips_rules_clear ();

    /* Rule parser cleanup -暂时注释掉，因为函数不存在 */
    // ips_rule_parser_cleanup ();
}

/**
 * @brief Load default rules on startup
 */
static clib_error_t *
ips_rules_load_default (void)
{
    ips_main_t *im = &ips_main;

    /* Set default rule file path */
    im->default_rules_file = format (0, "/etc/vpp/ips/suricata.rules%c", 0);

    /* Load default rules on startup if file exists - temporarily disabled */
    /*
    if (im->default_rules_file)
    {
        struct stat st;
        if (stat ((char *) im->default_rules_file, &st) == 0)
        {
            int rules_loaded = ips_load_rules_from_file_enhanced ((char *) im->default_rules_file);
            if (rules_loaded > 0)
            {
                clib_warning ("IPS: Loaded %d rules from %s on startup",
                             rules_loaded, im->default_rules_file);

                // Compile the loaded rules
                if (ips_rules_compile () >= 0)
                {
                    clib_warning ("IPS: Rules compiled successfully on startup");
                }
                else
                {
                    clib_warning ("IPS: Failed to compile rules on startup");
                }
            }
            else if (rules_loaded < 0)
            {
                clib_warning ("IPS: Failed to load rules from %s on startup",
                             im->default_rules_file);
            }
            else
            {
                clib_warning ("IPS: No rules found in %s", im->default_rules_file);
            }
        }
        else
        {
            clib_warning ("IPS: Default rules file %s not found, skipping startup load",
                         im->default_rules_file);
        }
    }
    */

    return 0;
}

/**
 * @brief Module init function
 */
static clib_error_t *
ips_rules_module_init_fn (vlib_main_t * vm)
{
    clib_error_t *error = 0;

    error = ips_rules_module_init ();
    if (error)
        return error;

    /* Load default rules */
    error = ips_rules_load_default ();
    if (error)
        clib_warning ("IPS: Failed to load default rules: %U", format_clib_error, error);

    return 0;
}

VLIB_INIT_FUNCTION (ips_rules_module_init_fn);