/*
 * ips_byte_operations.c - VPP IPS Byte Operations Implementation
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <vlib/vlib.h>
#include <vppinfra/string.h>
#include <ctype.h>

#include "ips_suricata_enhanced_engine.h"
#include "ips_suricata_rule_types.h"
#include "../ips_logging.h"

/**
 * @brief Extract bytes from data buffer
 */
static u32
ips_extract_bytes(const u8 *data, u32 data_len, u32 offset,
                 u8 num_bytes, u8 relative)
{
    if (!data || num_bytes == 0 || num_bytes > 4)
        return 0;

    if (relative && offset > 0)
        offset += offset;  /* This would be the relative offset from previous match */

    if (offset + num_bytes > data_len)
        return 0;  /* Out of bounds */

    u32 value = 0;
    for (int i = 0; i < num_bytes; i++) {
        value = (value << 8) | data[offset + i];
    }

    return value;
}

/**
 * @brief Convert string to integer with base detection
 */
static u32
ips_string_to_int(const char *str, u8 *base)
{
    if (!str)
        return 0;

    *base = 10;  /* Default to decimal */

    /* Skip leading whitespace */
    while (*str && isspace(*str))
        str++;

    /* Check for hex prefix */
    if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        *base = 16;
        str += 2;
    } else if (str[0] == '0') {
        *base = 8;  /* Octal */
        str++;
    }

    u32 value = 0;
    while (*str) {
        char c = *str++;
        u8 digit;

        if (c >= '0' && c <= '9') {
            digit = c - '0';
        } else if (c >= 'a' && c <= 'f' && *base == 16) {
            digit = 10 + (c - 'a');
        } else if (c >= 'A' && c <= 'F' && *base == 16) {
            digit = 10 + (c - 'A');
        } else {
            break;  /* Invalid character */
        }

        if (digit >= *base)
            break;  /* Invalid digit for base */

        value = value * *base + digit;
    }

    return value;
}

/**
 * @brief Parse byte_test parameters from string
 */
int
ips_parse_byte_test(const char *params, ips_byte_test_t *byte_test)
{
    if (!params || !byte_test)
        return -1;

    clib_memset(byte_test, 0, sizeof(*byte_test));

    char param_copy[256];
    clib_strncpy(param_copy, params, sizeof(param_copy) - 1);

    char *token = strtok(param_copy, ",");
    u32 param_index = 0;

    while (token && param_index < 6) {
        /* Skip leading whitespace */
        while (*token && isspace(*token))
            token++;

        switch (param_index) {
        case 0:  /* bytes to extract */
            byte_test->bytes = atoi(token);
            if (byte_test->bytes < 1 || byte_test->bytes > 4)
                return -1;
            break;

        case 1:  /* operator */
            if (strcmp(token, "=") == 0 || strcmp(token, "==") == 0) {
                byte_test->op = IPS_BYTE_TEST_EQ;
            } else if (strcmp(token, "!") == 0 || strcmp(token, "!=") == 0) {
                byte_test->op = IPS_BYTE_TEST_NE;  /* Not implemented */
            } else if (strcmp(token, "<") == 0) {
                byte_test->op = IPS_BYTE_TEST_LT;
            } else if (strcmp(token, ">") == 0) {
                byte_test->op = IPS_BYTE_TEST_GT;
            } else if (strcmp(token, "<=") == 0) {
                byte_test->op = IPS_BYTE_TEST_LE;
            } else if (strcmp(token, ">=") == 0) {
                byte_test->op = IPS_BYTE_TEST_GE;
            } else if (strcmp(token, "&") == 0 || strcmp(token, "&&") == 0) {
                byte_test->op = IPS_BYTE_TEST_AND;
            } else if (strcmp(token, "|") == 0 || strcmp(token, "||") == 0) {
                byte_test->op = IPS_BYTE_TEST_OR;
            } else if (strcmp(token, "^") == 0) {
                byte_test->op = IPS_BYTE_TEST_XOR;
            } else {
                return -1;  /* Invalid operator */
            }
            break;

        case 2:  /* value */
            byte_test->value = ips_string_to_int(token, &byte_test->base);
            break;

        case 3:  /* offset */
            byte_test->offset = atoi(token);
            break;

        case 4:  /* relative flag */
            if (strcmp(token, "relative") == 0) {
                byte_test->relative = 1;
            }
            break;

        case 5:  /* mask */
            if (strncmp(token, "mask", 4) == 0) {
                char *mask_str = token + 5;  /* Skip "mask " */
                if (*mask_str == '0' && (*(mask_str+1) == 'x' || *(mask_str+1) == 'X')) {
                    mask_str += 2;  /* Skip "0x" */
                }
                byte_test->mask = ips_string_to_int(mask_str, &byte_test->base);
            }
            break;
        }

        token = strtok(NULL, ",");
        param_index++;
    }

    /* Validate required parameters */
    if (byte_test->bytes == 0 || param_index < 3) {
        return -1;
    }

    return 0;
}

/**
 * @brief Parse byte_jump parameters from string
 */
int
ips_parse_byte_jump(const char *params, ips_byte_jump_t *byte_jump)
{
    if (!params || !byte_jump)
        return -1;

    clib_memset(byte_jump, 0, sizeof(*byte_jump));

    char param_copy[256];
    clib_strncpy(param_copy, params, sizeof(param_copy) - 1);

    char *token = strtok(param_copy, ",");
    u32 param_index = 0;

    while (token && param_index < 8) {
        /* Skip leading whitespace */
        while (*token && isspace(*token))
            token++;

        switch (param_index) {
        case 0:  /* bytes to convert */
            byte_jump->bytes = atoi(token);
            if (byte_jump->bytes < 1 || byte_jump->bytes > 4)
                return -1;
            break;

        case 1:  /* offset */
            byte_jump->offset = atoi(token);
            break;

        case 2:  /* multiplier */
            byte_jump->multiplier = atoi(token);
            break;

        case 3:  /* relative flag */
            if (strcmp(token, "relative") == 0) {
                byte_jump->relative = 1;
                byte_jump->modifiers |= IPS_BYTE_JUMP_RELATIVE;
            }
            break;

        case 4:  /* alignment */
            if (strcmp(token, "align") == 0) {
                byte_jump->modifiers |= IPS_BYTE_JUMP_ALIGN;
            }
            break;

        case 5:  /* from beginning */
            if (strcmp(token, "from_beginning") == 0) {
                byte_jump->modifiers |= IPS_BYTE_JUMP_FROM_BEGINNING;
            }
            break;

        case 6:  /* from end */
            if (strcmp(token, "from_end") == 0) {
                byte_jump->modifiers |= IPS_BYTE_JUMP_FROM_END;
            }
            break;

        case 7:  /* post offset */
            if (strncmp(token, "post_offset", 10) == 0) {
                char *offset_str = token + 11;  /* Skip "post_offset " */
                byte_jump->post_offset = atoi(offset_str);
                byte_jump->modifiers |= IPS_BYTE_JUMP_POST_OFFSET;
            }
            break;
        }

        token = strtok(NULL, ",");
        param_index++;
    }

    /* Validate required parameters */
    if (byte_jump->bytes == 0 || param_index < 2) {
        return -1;
    }

    return 0;
}

/**
 * @brief Execute byte_test operation
 */
int
ips_byte_test_execute(const ips_byte_test_t *byte_test,
                     const u8 *data, u32 data_len,
                     u32 *relative_offset)
{
    if (!byte_test || !data || !relative_offset)
        return -1;

    u32 offset = byte_test->offset;
    if (byte_test->relative && *relative_offset > 0) {
        offset += *relative_offset;
    }

    /* Extract bytes */
    u32 value = ips_extract_bytes(data, data_len, offset, byte_test->bytes, 0);
    if (value == 0 && offset + byte_test->bytes > data_len) {
        return 0;  /* Out of bounds, test fails */
    }

    /* Apply mask if specified */
    if (byte_test->mask) {
        value &= byte_test->mask;
    }

    /* Perform comparison */
    int result = 0;
    switch (byte_test->op) {
    case IPS_BYTE_TEST_EQ:
        result = (value == byte_test->value);
        break;
    case IPS_BYTE_TEST_NE:
        result = (value != byte_test->value);
        break;
    case IPS_BYTE_TEST_LT:
        result = (value < byte_test->value);
        break;
    case IPS_BYTE_TEST_GT:
        result = (value > byte_test->value);
        break;
    case IPS_BYTE_TEST_LE:
        result = (value <= byte_test->value);
        break;
    case IPS_BYTE_TEST_GE:
        result = (value >= byte_test->value);
        break;
    case IPS_BYTE_TEST_AND:
        result = (value & byte_test->value) != 0;
        break;
    case IPS_BYTE_TEST_OR:
        result = (value | byte_test->value) != 0;
        break;
    case IPS_BYTE_TEST_XOR:
        result = (value ^ byte_test->value) != 0;
        break;
    default:
        return -1;  /* Invalid operator */
    }

    /* Update relative offset if test passed */
    if (result && byte_test->relative) {
        *relative_offset = offset + byte_test->bytes;
    }

    return result;
}

/**
 * @brief Execute byte_jump operation
 */
int
ips_byte_jump_execute(const ips_byte_jump_t *byte_jump,
                     const u8 *data, u32 data_len,
                     u32 *relative_offset)
{
    if (!byte_jump || !data || !relative_offset)
        return -1;

    u32 offset = byte_jump->offset;
    if (byte_jump->relative && *relative_offset > 0) {
        offset += *relative_offset;
    }

    /* Handle special modifiers */
    if (byte_jump->modifiers & IPS_BYTE_JUMP_FROM_BEGINNING) {
        offset = byte_jump->offset;
    } else if (byte_jump->modifiers & IPS_BYTE_JUMP_FROM_END) {
        offset = data_len - byte_jump->offset;
    }

    /* Extract bytes */
    u32 value = ips_extract_bytes(data, data_len, offset, byte_jump->bytes, 0);
    if (offset + byte_jump->bytes > data_len) {
        return -1;  /* Out of bounds */
    }

    /* Apply multiplier */
    if (byte_jump->multiplier > 1) {
        value *= byte_jump->multiplier;
    }

    /* Apply alignment if specified */
    if (byte_jump->modifiers & IPS_BYTE_JUMP_ALIGN) {
        u32 alignment = byte_jump->bytes;
        if (alignment > 0) {
            value = (value + alignment - 1) & ~(alignment - 1);
        }
    }

    /* Calculate new offset */
    u32 new_offset = value;

    if (byte_jump->modifiers & IPS_BYTE_JUMP_POST_OFFSET) {
        new_offset += byte_jump->post_offset;
    }

    /* Update relative offset */
    *relative_offset = new_offset;

    return 0;
}

/**
 * @brief Check byte_test options for a rule
 */
int
ips_byte_test_check_rule(ips_suricata_rule_t *rule,
                         const u8 *data, u32 data_len,
                         u32 *relative_offset)
{
    if (!rule || !data || !relative_offset)
        return 1;  /* No byte tests to check, rule passes */

    for (u32 i = 0; i < rule->byte_test_count; i++) {
        ips_byte_test_t *byte_test = &rule->byte_tests[i];

        int result = ips_byte_test_execute(byte_test, data, data_len, relative_offset);
        if (result <= 0) {
            return 0;  /* Byte test failed, rule fails */
        }
    }

    return 1;  /* All byte tests passed */
}

/**
 * @brief Execute byte_jump options for a rule
 */
int
ips_byte_jump_execute_rule(ips_suricata_rule_t *rule,
                           const u8 *data, u32 data_len,
                           u32 *relative_offset)
{
    if (!rule || !data || !relative_offset)
        return 0;  /* No byte jumps to execute */

    for (u32 i = 0; i < rule->byte_jump_count; i++) {
        ips_byte_jump_t *byte_jump = &rule->byte_jumps[i];

        if (ips_byte_jump_execute(byte_jump, data, data_len, relative_offset) < 0) {
            return -1;  /* Byte jump failed */
        }
    }

    return 0;  /* All byte jumps executed successfully */
}

/**
 * @brief Create byte_test from option value
 */
ips_byte_test_t *
ips_byte_test_create(const char *option_value)
{
    if (!option_value)
        return NULL;

    ips_byte_test_t *byte_test = clib_mem_alloc(sizeof(ips_byte_test_t));
    if (!byte_test)
        return NULL;

    if (ips_parse_byte_test(option_value, byte_test) < 0) {
        clib_mem_free(byte_test);
        return NULL;
    }

    return byte_test;
}

/**
 * @brief Create byte_jump from option value
 */
ips_byte_jump_t *
ips_byte_jump_create(const char *option_value)
{
    if (!option_value)
        return NULL;

    ips_byte_jump_t *byte_jump = clib_mem_alloc(sizeof(ips_byte_jump_t));
    if (!byte_jump)
        return NULL;

    if (ips_parse_byte_jump(option_value, byte_jump) < 0) {
        clib_mem_free(byte_jump);
        return NULL;
    }

    return byte_jump;
}

/**
 * @brief Free byte_test
 */
void
ips_byte_test_free(ips_byte_test_t *byte_test)
{
    if (byte_test)
        clib_mem_free(byte_test);
}

/**
 * @brief Free byte_jump
 */
void
ips_byte_jump_free(ips_byte_jump_t *byte_jump)
{
    if (byte_jump)
        clib_mem_free(byte_jump);
}