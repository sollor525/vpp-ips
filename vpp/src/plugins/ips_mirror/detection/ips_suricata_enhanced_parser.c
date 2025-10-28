/*
 * ips_suricata_enhanced_parser.c - VPP IPS Enhanced Suricata Rule Parser Implementation
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <vlib/vlib.h>
#include <vppinfra/string.h>
#include <vppinfra/format.h>
#include <ctype.h>
#include <stdarg.h>

#include "ips_suricata_enhanced_parser.h"
#include "../ips_logging.h"

/* Global parser state */
static ips_suricata_parser_state_t parser_state = {0};

/* Default parser configuration */
static const ips_suricata_parser_config_t default_config = {
    .strict_parsing = 1,
    .allow_comments = 1,
    .validate_content = 1,
    .optimize_rules = 1,
    .max_rule_length = IPS_MAX_RULE_LENGTH,
    .max_content_length = IPS_MAX_CONTENT_LENGTH,
    .max_pcre_length = IPS_MAX_PCRE_PATTERN_LENGTH,
};

/* Action string mappings */
static const struct {
    const char *name;
    ips_action_t action;
} action_strings[] = {
    {"alert", IPS_ACTION_ALERT},
    {"drop", IPS_ACTION_DROP},
    {"reject", IPS_ACTION_REJECT},
    {"log", IPS_ACTION_LOG},
    {"pass", IPS_ACTION_PASS},
};

/* Protocol string mappings */
static const struct {
    const char *name;
    ips_protocol_t protocol;
} protocol_strings[] = {
    {"tcp", IPS_PROTO_TCP},
    {"udp", IPS_PROTO_UDP},
    {"icmp", IPS_PROTO_ICMP},
    {"ip", IPS_PROTO_IP},
    {"any", IPS_PROTO_ANY},
};

/**
 * @brief Convert action string to enum
 */
ips_action_t
ips_string_to_action(const char *str)
{
    for (u32 i = 0; i < ARRAY_LEN(action_strings); i++)
    {
        if (strcasecmp(str, action_strings[i].name) == 0)
            return action_strings[i].action;
    }
    return IPS_ACTION_MAX;  /* Invalid */
}

/**
 * @brief Convert protocol string to enum
 */
ips_protocol_t
ips_string_to_protocol(const char *str)
{
    for (u32 i = 0; i < ARRAY_LEN(protocol_strings); i++)
    {
        if (strcasecmp(str, protocol_strings[i].name) == 0)
            return protocol_strings[i].protocol;
    }
    return IPS_PROTO_ANY;  /* Default to any */
}

/**
 * @brief Convert action enum to string
 */
const char *
ips_action_to_string(ips_action_t action)
{
    if (action < IPS_ACTION_MAX)
        return action_strings[action].name;
    return "unknown";
}

/**
 * @brief Convert protocol enum to string
 */
const char *
ips_protocol_to_string(ips_protocol_t proto)
{
    for (u32 i = 0; i < ARRAY_LEN(protocol_strings); i++)
    {
        if (protocol_strings[i].protocol == proto)
            return protocol_strings[i].name;
    }
    return "unknown";
}

/**
 * @brief Set parser error
 */
void
ips_suricata_parser_set_error(ips_suricata_parser_context_t *ctx,
                               const char *format, ...)
{
    if (!ctx)
        return;

    va_list args;
    va_start(args, format);
    vsnprintf(ctx->error_msg, sizeof(ctx->error_msg), format, args);
    va_end(args);

    ctx->has_error = 1;
}

/**
 * @brief Clear parser error
 */
void
ips_suricata_parser_clear_error(ips_suricata_parser_context_t *ctx)
{
    if (!ctx)
        return;

    ctx->has_error = 0;
    ctx->error_msg[0] = '\0';
}

/**
 * @brief Convert hex string to bytes
 */
int
ips_suricata_hex_to_bytes(const char *hex_str, u8 *bytes, u32 max_bytes)
{
    if (!hex_str || !bytes || max_bytes == 0)
        return -1;

    u32 len = strlen(hex_str);
    if (len % 2 != 0)
        return -1;  /* Must be even number of characters */

    u32 byte_count = 0;
    for (u32 i = 0; i < len && byte_count < max_bytes; i += 2)
    {
        u8 high, low;

        if (hex_str[i] >= '0' && hex_str[i] <= '9')
            high = hex_str[i] - '0';
        else if (hex_str[i] >= 'a' && hex_str[i] <= 'f')
            high = hex_str[i] - 'a' + 10;
        else if (hex_str[i] >= 'A' && hex_str[i] <= 'F')
            high = hex_str[i] - 'A' + 10;
        else
            return -1;  /* Invalid hex character */

        if (hex_str[i+1] >= '0' && hex_str[i+1] <= '9')
            low = hex_str[i+1] - '0';
        else if (hex_str[i+1] >= 'a' && hex_str[i+1] <= 'f')
            low = hex_str[i+1] - 'a' + 10;
        else if (hex_str[i+1] >= 'A' && hex_str[i+1] <= 'F')
            low = hex_str[i+1] - 'A' + 10;
        else
            return -1;  /* Invalid hex character */

        bytes[byte_count++] = (high << 4) | low;
    }

    return byte_count;
}

/**
 * @brief Unescape string
 */
int
ips_suricata_unescape_string(const char *str, char *escaped, u32 max_len)
{
    if (!str || !escaped || max_len == 0)
        return -1;

    u32 src_len = strlen(str);
    u32 dst_len = 0;

    for (u32 i = 0; i < src_len && dst_len < max_len - 1; i++)
    {
        if (str[i] == '\\' && i + 1 < src_len)
        {
            switch (str[i+1])
            {
            case 'n':
                escaped[dst_len++] = '\n';
                i++;
                break;
            case 'r':
                escaped[dst_len++] = '\r';
                i++;
                break;
            case 't':
                escaped[dst_len++] = '\t';
                i++;
                break;
            case '\\':
                escaped[dst_len++] = '\\';
                i++;
                break;
            case '"':
                escaped[dst_len++] = '"';
                i++;
                break;
            case ';':
                escaped[dst_len++] = ';';
                i++;
                break;
            default:
                /* Invalid escape, copy as-is */
                escaped[dst_len++] = str[i];
                break;
            }
        }
        else
        {
            escaped[dst_len++] = str[i];
        }
    }

    escaped[dst_len] = '\0';
    return dst_len;
}

/**
 * @brief Parse IP address/network specification
 */
int
ips_suricata_parse_ip_spec(const char *spec, ips_ip_spec_t *ip_spec)
{
    if (!spec || !ip_spec)
        return -1;

    /* Initialize to default */
    clib_memset(ip_spec, 0, sizeof(*ip_spec));
    ip_spec->is_any = 1;

    /* Handle "any" */
    if (strcasecmp(spec, "any") == 0)
        return 0;

    ip_spec->is_any = 0;

    /* Check for IPv6 */
    if (strchr(spec, ':') != NULL)
    {
        ip_spec->is_ipv6 = 1;
        /* TODO: Implement IPv6 parsing */
        return -1;  /* Not implemented yet */
    }

    /* Parse IPv4 address */
    char addr_str[64];
    char mask_str[64] = "255.255.255.255";
    char *slash = strchr(spec, '/');

    if (slash)
    {
        u32 addr_len = slash - spec;
        if (addr_len >= sizeof(addr_str))
            return -1;

        clib_memcpy(addr_str, spec, addr_len);
        addr_str[addr_len] = '\0';
        clib_strncpy(mask_str, slash + 1, sizeof(mask_str) - 1);
    }
    else
    {
        clib_strncpy(addr_str, spec, sizeof(addr_str) - 1);
    }

    /* Parse address */
    /* TODO: Implement IP address parsing - ip4_address_parse not available */
    // if (ip4_address_parse(addr_str, &ip_spec->addr.ip4) < 0)
    //     return -1;

    /* Parse mask */
    if (strchr(mask_str, '.') != NULL)
    {
        /* Dotted decimal mask */
        /* TODO: Implement IP address parsing - ip4_address_parse not available */
        // if (ip4_address_parse(mask_str, &ip_spec->mask.ip4) < 0)
        //     return -1;
    }
    else
    {
        /* CIDR notation */
        u32 prefix_len = atoi(mask_str);
        if (prefix_len > 32)
            return -1;

        if (prefix_len == 0)
        {
            ip_spec->mask.ip4.as_u32 = 0x00000000;
        }
        else
        {
            ip_spec->mask.ip4.as_u32 = clib_host_to_net_u32(~((1ULL << (32 - prefix_len)) - 1));
        }
    }

    return 0;
}

/**
 * @brief Parse port specification
 */
int
ips_suricata_parse_port_spec(const char *spec, ips_port_spec_t *port_spec)
{
    if (!spec || !port_spec)
        return -1;

    /* Initialize to default */
    clib_memset(port_spec, 0, sizeof(*port_spec));
    port_spec->is_any = 1;

    /* Handle "any" */
    if (strcasecmp(spec, "any") == 0)
        return 0;

    port_spec->is_any = 0;

    /* Check for range */
    char *dash = strchr(spec, '-');
    if (dash)
    {
        *dash = '\0';
        port_spec->start = atoi(spec);
        port_spec->end = atoi(dash + 1);
        *dash = '-';
    }
    else
    {
        port_spec->start = port_spec->end = atoi(spec);
    }

    /* Validate port range */
    if (port_spec->start > 65535 || port_spec->end > 65535 ||
        port_spec->start > port_spec->end)
        return -1;

    return 0;
}

/**
 * @brief Check if string represents valid keyword
 */
int
ips_suricata_is_valid_keyword(const char *str)
{
    if (!str || strlen(str) == 0)
        return 0;

    /* Check each character */
    for (u32 i = 0; str[i]; i++)
    {
        if (!isalnum(str[i]) && str[i] != '_' && str[i] != '-')
            return 0;
    }

    return 1;
}

/**
 * @brief Create a new rule
 */
ips_suricata_rule_t *
ips_suricata_rule_create(void)
{
    ips_suricata_rule_t *rule = clib_mem_alloc(sizeof(ips_suricata_rule_t));
    if (!rule)
        return NULL;

    clib_memset(rule, 0, sizeof(*rule));

    /* Set default values */
    rule->gid = 1;  /* Default generator ID */
    rule->priority = 1;
    rule->enabled = 1;
    rule->protocol = IPS_PROTO_IP;
    rule->direction = IPS_DIR_ANY;

    /* Set default IP specs to "any" */
    ips_suricata_parse_ip_spec("any", &rule->src_ip);
    ips_suricata_parse_ip_spec("any", &rule->dst_ip);

    /* Set default port specs to "any" */
    ips_suricata_parse_port_spec("any", &rule->src_port);
    ips_suricata_parse_port_spec("any", &rule->dst_port);

    return rule;
}

/**
 * @brief Free a rule
 */
void
ips_suricata_rule_free(ips_suricata_rule_t *rule)
{
    if (!rule)
        return;

    /* Free content matches */
    if (rule->contents)
    {
        for (u32 i = 0; i < rule->content_count; i++)
        {
            ips_content_match_free(&rule->contents[i]);
        }
        vec_free(rule->contents);
    }

    /* Free PCRE patterns */
    if (rule->pcre_patterns)
    {
        for (u32 i = 0; i < rule->pcre_count; i++)
        {
            ips_pcre_match_free(&rule->pcre_patterns[i]);
        }
        vec_free(rule->pcre_patterns);
    }

    /* Free byte tests */
    if (rule->byte_tests)
    {
        for (u32 i = 0; i < rule->byte_test_count; i++)
        {
            clib_mem_free(&rule->byte_tests[i]);
        }
        vec_free(rule->byte_tests);
    }

    /* Free byte jumps */
    if (rule->byte_jumps)
    {
        for (u32 i = 0; i < rule->byte_jump_count; i++)
        {
            clib_mem_free(&rule->byte_jumps[i]);
        }
        vec_free(rule->byte_jumps);
    }

    /* Free flowbits */
    if (rule->flowbits)
    {
        for (u32 i = 0; i < rule->flowbit_count; i++)
        {
            ips_flowbit_free(&rule->flowbits[i]);
        }
        vec_free(rule->flowbits);
    }

    clib_mem_free(rule);
}

/**
 * @brief Create content match
 */
ips_content_match_t *
ips_content_match_create(void)
{
    ips_content_match_t *content = clib_mem_alloc(sizeof(ips_content_match_t));
    if (!content)
        return NULL;

    clib_memset(content, 0, sizeof(*content));
    return content;
}

/**
 * @brief Free content match
 */
void
ips_content_match_free(ips_content_match_t *content)
{
    if (!content)
        return;

    if (content->pattern)
        clib_mem_free(content->pattern);
    if (content->hex_pattern)
        clib_mem_free(content->hex_pattern);

    clib_mem_free(content);
}

/**
 * @brief Add pattern to content match
 */
int
ips_content_match_add_pattern(ips_content_match_t *content, const u8 *pattern, u32 len)
{
    if (!content || !pattern || len == 0)
        return -1;

    if (content->pattern)
        clib_mem_free(content->pattern);

    content->pattern = clib_mem_alloc(len);
    if (!content->pattern)
        return -1;

    clib_memcpy(content->pattern, pattern, len);
    content->pattern_len = len;

    return 0;
}

/**
 * @brief Calculate rule hash
 */
u32
ips_suricata_rule_hash(ips_suricata_rule_t *rule)
{
    if (!rule)
        return 0;

    /* Simple hash based on SID and revision */
    u32 hash = rule->sid;
    hash = (hash << 16) ^ rule->rev;
    hash = (hash << 8) ^ rule->gid;

    return hash;
}

/**
 * @brief Initialize parser
 */
int
ips_suricata_parser_init(const ips_suricata_parser_config_t *config)
{
    /* Clear global state */
    clib_memset(&parser_state, 0, sizeof(parser_state));

    /* Use provided config or defaults */
    if (config)
        parser_state.config = *config;
    else
        parser_state.config = default_config;

    return 0;
}

/**
 * @brief Cleanup parser
 */
void
ips_suricata_parser_cleanup(void)
{
    clib_memset(&parser_state, 0, sizeof(parser_state));
}

/**
 * @brief Parse rule header
 */
int
ips_suricata_parse_rule_header(ips_suricata_parser_context_t *ctx,
                               const char *rule_text,
                               u32 *char_index,
                               ips_suricata_rule_t *rule)
{
    if (!ctx || !rule_text || !char_index || !rule)
        return -1;

    char buffer[1024];
    u32 i = *char_index;

    /* Skip leading whitespace */
    while (rule_text[i] && isspace(rule_text[i]))
        i++;

    /* Parse action */
    u32 start = i;
    while (rule_text[i] && !isspace(rule_text[i]))
        i++;

    if (i - start >= sizeof(buffer))
    {
        ips_suricata_parser_set_error(ctx, "Action too long");
        return -1;
    }

    clib_memcpy(buffer, &rule_text[start], i - start);
    buffer[i - start] = '\0';

    rule->action = ips_string_to_action(buffer);
    if (rule->action == IPS_ACTION_MAX)
    {
        ips_suricata_parser_set_error(ctx, "Invalid action: %s", buffer);
        return -1;
    }

    /* Skip whitespace */
    while (rule_text[i] && isspace(rule_text[i]))
        i++;

    /* Parse protocol */
    start = i;
    while (rule_text[i] && !isspace(rule_text[i]))
        i++;

    if (i - start >= sizeof(buffer))
    {
        ips_suricata_parser_set_error(ctx, "Protocol too long");
        return -1;
    }

    clib_memcpy(buffer, &rule_text[start], i - start);
    buffer[i - start] = '\0';

    rule->protocol = ips_string_to_protocol(buffer);

    /* Continue parsing remaining header elements... */
    /* TODO: Implement full header parsing */

    *char_index = i;
    return 0;
}

/**
 * @brief Parse content option
 */
int
ips_suricata_parse_content_option(ips_suricata_parser_context_t *ctx,
                                  const char *value,
                                  ips_suricata_rule_t *rule)
{
    if (!ctx || !value || !rule)
        return -1;

    /* Create new content match */
    ips_content_match_t *content = ips_content_match_create();
    if (!content)
    {
        ips_suricata_parser_set_error(ctx, "Memory allocation failed");
        return -1;
    }

    /* Parse content value */
    if (value[0] == '"' && value[strlen(value) - 1] == '"')
    {
        /* Quoted string content */
        char unescaped[IPS_MAX_CONTENT_LENGTH];
        u32 len = strlen(value) - 2;  /* Remove quotes */

        if (len >= sizeof(unescaped))
        {
            ips_suricata_parser_set_error(ctx, "Content too long");
            ips_content_match_free(content);
            return -1;
        }

        char temp[IPS_MAX_CONTENT_LENGTH];
        clib_memcpy(temp, &value[1], len);
        temp[len] = '\0';

        len = ips_suricata_unescape_string(temp, unescaped, sizeof(unescaped));
        if (len < 0)
        {
            ips_suricata_parser_set_error(ctx, "Invalid escape sequence in content");
            ips_content_match_free(content);
            return -1;
        }

        if (ips_content_match_add_pattern(content, (u8*)unescaped, len) < 0)
        {
            ips_suricata_parser_set_error(ctx, "Failed to add content pattern");
            ips_content_match_free(content);
            return -1;
        }
    }
    else if (value[0] == '|' && value[strlen(value) - 1] == '|')
    {
        /* Hex string content */
        char hex_str[IPS_MAX_CONTENT_LENGTH * 2];
        u32 len = strlen(value) - 2;  /* Remove pipes */

        if (len >= sizeof(hex_str))
        {
            ips_suricata_parser_set_error(ctx, "Hex content too long");
            ips_content_match_free(content);
            return -1;
        }

        clib_memcpy(hex_str, &value[1], len);
        hex_str[len] = '\0';

        /* Remove spaces from hex string */
        char *dst = hex_str;
        for (u32 i = 0; i < len; i++)
        {
            if (!isspace(hex_str[i]))
                *dst++ = hex_str[i];
        }
        *dst = '\0';

        u8 bytes[IPS_MAX_CONTENT_LENGTH];
        int byte_count = ips_suricata_hex_to_bytes(hex_str, bytes, sizeof(bytes));
        if (byte_count < 0)
        {
            ips_suricata_parser_set_error(ctx, "Invalid hex string in content");
            ips_content_match_free(content);
            return -1;
        }

        if (ips_content_match_add_pattern(content, bytes, byte_count) < 0)
        {
            ips_suricata_parser_set_error(ctx, "Failed to add hex content");
            ips_content_match_free(content);
            return -1;
        }

        content->modifiers |= IPS_CONTENT_MOD_RAWBYTES;
    }
    else
    {
        ips_suricata_parser_set_error(ctx, "Content must be quoted string or hex string");
        ips_content_match_free(content);
        return -1;
    }

    /* Add content to rule */
    vec_add1(rule->contents, *content);
    rule->content_count++;

    /* Update rule metadata */
    if (content->modifiers & (IPS_CONTENT_MOD_HTTP_METHOD | IPS_CONTENT_MOD_HTTP_URI |
                              IPS_CONTENT_MOD_HTTP_HEADER | IPS_CONTENT_MOD_HTTP_CLIENT_BODY |
                              IPS_CONTENT_MOD_HTTP_SERVER_BODY | IPS_CONTENT_MOD_HTTP_COOKIE |
                              IPS_CONTENT_MOD_HTTP_USER_AGENT | IPS_CONTENT_MOD_HTTP_HOST))
    {
        rule->has_http_content = 1;
    }

    if (rule->content_min_len == 0 || content->pattern_len < rule->content_min_len)
        rule->content_min_len = content->pattern_len;

    clib_mem_free(content);
    return 0;
}

/**
 * @brief Parse a single rule
 */
ips_suricata_rule_t *
ips_suricata_parse_rule(const char *rule_text,
                        const char *filename,
                        u32 line_number)
{
    if (!rule_text || strlen(rule_text) == 0)
        return NULL;

    /* Create parser context */
    ips_suricata_parser_context_t ctx = {0};
    ctx.input = rule_text;
    ctx.filename = filename ? filename : "<unknown>";
    ctx.line_number = line_number;
    ctx.char_position = 0;

    /* Create rule */
    ips_suricata_rule_t *rule = ips_suricata_rule_create();
    if (!rule)
    {
        ips_suricata_parser_set_error(&ctx, "Failed to allocate rule");
        return NULL;
    }

    /* Skip comments and empty lines */
    const char *p = rule_text;
    while (*p && isspace(*p))
        p++;

    if (*p == '#' || *p == '\0')
    {
        ips_suricata_rule_free(rule);
        return NULL;  /* Skip comments and empty lines */
    }

    u32 char_index = 0;

    /* Parse rule header */
    if (ips_suricata_parse_rule_header(&ctx, rule_text, &char_index, rule) < 0)
    {
        if (parser_state.config.strict_parsing)
        {
            ips_log_system_async(IPS_LOG_LEVEL_ERROR,
                                "Rule parse error (%s:%u): %s",
                                ctx.filename, ctx.line_number, ctx.error_msg);
            ips_suricata_rule_free(rule);
            return NULL;
        }
        else
        {
            rule->has_error = 1;
            clib_strncpy(rule->error_msg, ctx.error_msg, sizeof(rule->error_msg) - 1);
        }
    }

    /* Find start of options */
    const char *options_start = strchr(rule_text + char_index, '(');
    if (!options_start)
    {
        ips_suricata_parser_set_error(&ctx, "Missing options parentheses");
        if (parser_state.config.strict_parsing)
        {
            ips_suricata_rule_free(rule);
            return NULL;
        }
        else
        {
            rule->has_error = 1;
            clib_strncpy(rule->error_msg, ctx.error_msg, sizeof(rule->error_msg) - 1);
            return rule;
        }
    }

    options_start++;  /* Skip '(' */

    /* Find end of options */
    const char *options_end = strrchr(options_start, ')');
    if (!options_end)
    {
        ips_suricata_parser_set_error(&ctx, "Missing closing parenthesis");
        if (parser_state.config.strict_parsing)
        {
            ips_suricata_rule_free(rule);
            return NULL;
        }
        else
        {
            rule->has_error = 1;
            clib_strncpy(rule->error_msg, ctx.error_msg, sizeof(rule->error_msg) - 1);
            return rule;
        }
    }

    /* Parse options */
    char *options_copy = clib_mem_alloc(options_end - options_start + 1);
    if (!options_copy)
    {
        ips_suricata_parser_set_error(&ctx, "Memory allocation failed");
        ips_suricata_rule_free(rule);
        return NULL;
    }

    clib_memcpy(options_copy, options_start, options_end - options_start);
    options_copy[options_end - options_start] = '\0';

    /* TODO: Implement full option parsing */
    /* For now, just parse basic content options */
    char *option = strtok(options_copy, ";");
    while (option)
    {
        /* Skip leading whitespace */
        while (*option && isspace(*option))
            option++;

        if (*option == '\0')
        {
            option = strtok(NULL, ";");
            continue;
        }

        /* Parse option name and value */
        char *colon = strchr(option, ':');
        if (colon)
        {
            *colon = '\0';
            char *option_name = option;
            char *option_value = colon + 1;

            /* Trim whitespace */
            while (*option_name && isspace(*option_name))
                option_name++;
            while (*option_value && isspace(*option_value))
                option_value++;

            /* Parse specific options */
            if (strcmp(option_name, "msg") == 0)
            {
                /* Parse message */
                if (option_value[0] == '"' && option_value[strlen(option_value) - 1] == '"')
                {
                    u32 len = strlen(option_value) - 2;
                    if (len < sizeof(rule->msg))
                    {
                        clib_memcpy(rule->msg, &option_value[1], len);
                        rule->msg[len] = '\0';
                    }
                }
            }
            else if (strcmp(option_name, "sid") == 0)
            {
                rule->sid = atoi(option_value);
            }
            else if (strcmp(option_name, "rev") == 0)
            {
                rule->rev = atoi(option_value);
            }
            else if (strcmp(option_name, "gid") == 0)
            {
                rule->gid = atoi(option_value);
            }
            else if (strcmp(option_name, "priority") == 0)
            {
                rule->priority = atoi(option_value);
            }
            else if (strcmp(option_name, "content") == 0)
            {
                if (ips_suricata_parse_content_option(&ctx, option_value, rule) < 0)
                {
                    /* Error already set by parser */
                    if (parser_state.config.strict_parsing)
                    {
                        clib_mem_free(options_copy);
                        ips_suricata_rule_free(rule);
                        return NULL;
                    }
                }
            }
            /* TODO: Add more option parsers */
        }

        option = strtok(NULL, ";");
    }

    clib_mem_free(options_copy);

    /* Calculate rule hash */
    rule->rule_hash = ips_suricata_rule_hash(rule);

    /* Mark as parsed */
    rule->parsed = 1;

    return rule;
}

/**
 * @brief Parse rules from file
 */
int
ips_suricata_parse_rules_file(const char *filename,
                              ips_suricata_rule_table_t *rule_table)
{
    if (!filename || !rule_table)
        return -1;

    FILE *fp = fopen(filename, "r");
    if (!fp)
    {
        ips_log_system_async(IPS_LOG_LEVEL_ERROR,
                            "Failed to open rules file: %s", filename);
        return -1;
    }

    char line[IPS_MAX_RULE_LENGTH];
    u32 line_number = 0;
    u32 rules_loaded = 0;

    while (fgets(line, sizeof(line), fp))
    {
        line_number++;
        u32 len = strlen(line);

        /* Remove trailing newline */
        if (len > 0 && line[len-1] == '\n')
        {
            line[len-1] = '\0';
            len--;
        }

        /* Skip empty lines and comments */
        if (len == 0 || line[0] == '#')
            continue;

        /* Parse rule */
        ips_suricata_rule_t *rule = ips_suricata_parse_rule(line, filename, line_number);
        if (rule)
        {
            /* TODO: Add rule to rule table */
            rules_loaded++;

            if (rule->has_error)
            {
                ips_log_system_async(IPS_LOG_LEVEL_WARNING,
                                    "Rule parsed with errors (%s:%u): %s",
                                    filename, line_number, rule->error_msg);
            }
            else
            {
                ips_log_system_async(IPS_LOG_LEVEL_DEBUG,
                                    "Successfully loaded rule SID:%u GID:%u",
                                    rule->sid, rule->gid);
            }
        }
        else
        {
            parser_state.rules_with_errors++;
        }

        parser_state.rules_parsed++;
    }

    fclose(fp);

    ips_log_system_async(IPS_LOG_LEVEL_INFO,
                        "Parsed %u rules from %s (%u loaded, %u errors)",
                        parser_state.rules_parsed, filename, rules_loaded,
                        parser_state.rules_with_errors);

    return rules_loaded;
}

/**
 * @brief Get parser statistics
 */
void
ips_suricata_parser_get_stats(u32 *rules_parsed,
                              u32 *rules_loaded,
                              u32 *rules_with_errors,
                              f64 *parse_time)
{
    if (rules_parsed)
        *rules_parsed = parser_state.rules_parsed;
    if (rules_loaded)
        *rules_loaded = parser_state.rules_loaded;
    if (rules_with_errors)
        *rules_with_errors = parser_state.rules_with_errors;
    if (parse_time)
        *parse_time = parser_state.parse_time;
}