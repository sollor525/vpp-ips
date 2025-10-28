/*
 * ips_block_cli.c - IPS Blocking Module CLI Commands
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/interface.h>
#include "ips_block.h"

/**
 * @brief CLI command to set block TX interface
 */
static clib_error_t *
ips_block_set_interface_command_fn(vlib_main_t *vm,
                                  unformat_input_t *input,
                                  vlib_cli_command_t *cmd)
{
    (void)cmd;
    unformat_input_t _line_input, *line_input = &_line_input;
    vnet_main_t *vnm = vnet_get_main();
    u32 sw_if_index = ~0;
    u8 use_rx = 0;

    /* Get input */
    if (!unformat_user(input, unformat_line_input, line_input))
        return clib_error_return(0, "Missing interface name or 'rx'");

    /* Parse options */
    while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat(line_input, "rx"))
        {
            use_rx = 1;
            break;
        }
        else if (unformat(line_input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
        {
            /* Interface parsed */
            break;
        }
        else
        {
            unformat_free(line_input);
            return clib_error_return(0, "Unknown input '%U'", format_unformat_error, line_input);
        }
    }

    unformat_free(line_input);

    /* Apply configuration */
    if (use_rx)
    {
        sw_if_index = ~0;
    }

    if (ips_block_set_tx_interface(sw_if_index) != 0)
    {
        return clib_error_return(0, "Failed to set block TX interface");
    }

    if (use_rx || sw_if_index == ~0)
    {
        vlib_cli_output(vm, "Block packets will be sent on same interface as RX");
    }
    else
    {
        vlib_cli_output(vm, "Block packets will be sent on interface %U",
                       format_vnet_sw_if_index_name, vnm, sw_if_index);
    }

    return 0;
}

/**
 * @brief CLI command to show block configuration
 */
static clib_error_t *
ips_block_show_config_command_fn(vlib_main_t *vm,
                                unformat_input_t *input,
                                vlib_cli_command_t *cmd)
{
    (void)input;
    (void)cmd;
    
    vnet_main_t *vnm = vnet_get_main();
    u32 sw_if_index = ips_block_get_tx_interface();
    
    extern ips_block_manager_t ips_block_manager;
    ips_block_manager_t *bm = &ips_block_manager;

    vlib_cli_output(vm, "IPS Blocking Configuration:");
    vlib_cli_output(vm, "  Logging:          %s", bm->enable_logging ? "enabled" : "disabled");
    vlib_cli_output(vm, "  Rate limiting:    %s", bm->rate_limit_enabled ? "enabled" : "disabled");
    
    if (bm->rate_limit_enabled)
    {
        vlib_cli_output(vm, "  Max blocks/sec:   %u (per thread)", bm->max_blocks_per_second);
    }
    
    vlib_cli_output(vm, "");
    vlib_cli_output(vm, "Block TX Interface:");
    
    if (sw_if_index == ~0)
    {
        vlib_cli_output(vm, "  Mode:             Use same interface as RX (default)");
    }
    else
    {
        vlib_cli_output(vm, "  Mode:             Fixed interface");
        vlib_cli_output(vm, "  Interface:        %U",
                       format_vnet_sw_if_index_name, vnm, sw_if_index);
    }

    return 0;
}

/* CLI command definitions */
VLIB_CLI_COMMAND(ips_block_set_interface_command, static) = {
    .path = "ips block set interface",
    .short_help = "ips block set interface <interface-name> | rx",
    .function = ips_block_set_interface_command_fn,
};

VLIB_CLI_COMMAND(ips_block_show_config_command, static) = {
    .path = "show ips block config",
    .short_help = "show ips block config",
    .function = ips_block_show_config_command_fn,
};
