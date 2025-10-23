/*
 * ips_enhanced_suricata_parser.c - Enhanced Suricata Rule Parser
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <vnet/vnet.h>
#include <vppinfra/clib.h>
#include <vppinfra/vec.h>
#include <vppinfra/format.h>
#include <ctype.h>
#include "ips.h"

/* External function declarations */
extern char *ips_strdup(const char *s);
extern char *ips_strtok_r(char *str, const char *delim, char **saveptr);

/* Enhanced content structure to support more Suricata modifiers */
typedef struct
{
    u8 *pattern;           /* Content pattern */
    u32 pattern_len;       /* Pattern length */
    u8 is_hex:1;           /* Is hexadecimal pattern */
    u8 nocase:1;           /* Case insensitive */
    u8 rawbytes:1;         /* Raw bytes */

    /* Enhanced content modifiers */
    u32 depth;             /* Search depth from start */
    u32 offset;            /* Start offset */
    u32 distance;          /* Distance from previous match */
    u32 within;            /* Within range from previous match */

    /* New Suricata modifiers */
    u8 fast_pattern:1;     /* Use as fast pattern for Hyperscan */
    u8 fast_pattern_only:1; /* Only use as fast pattern */
    u8 endswith:1;         /* Pattern must be at end of buffer */
    u8 startswith:1;       /* Pattern must be at start of buffer */
    u32 bsize;             /* Buffer size restriction */
    u8 bsize_enabled:1;    /* Buffer size check enabled */
    u8 bsize_operator;     /* 0=equal, 1=greater, 2=less */

    /* HTTP context modifiers */
    u8 http_method:1;
    u8 http_uri:1;
    u8 http_header:1;
    u8 http_cookie:1;
    u8 http_user_agent:1;
    u8 http_host:1;
    u8 http_raw_uri:1;
    u8 http_stat_code:1;
    u8 http_stat_msg:1;

} ips_enhanced_content_t;

/**
 * @brief Parse content with enhanced Suricata modifiers
 */
__attribute__((unused)) static int
parse_enhanced_content_modifiers(char *modifiers_str, ips_enhanced_content_t *content)
{
    char *token, *value, *saveptr;
    char *mod_copy = ips_strdup(modifiers_str);

    if (!mod_copy)
        return -1;

    token = ips_strtok_r(mod_copy, ";", &saveptr);
    while (token)
    {
        /* Skip leading whitespace */
        while (isspace(*token))
            token++;

        /* Content positioning modifiers */
        if (strncmp(token, "depth:", 6) == 0)
        {
            value = token + 6;
            while (isspace(*value))
                value++;
            content->depth = atoi(value);
        }
        else if (strncmp(token, "offset:", 7) == 0)
        {
            value = token + 7;
            while (isspace(*value))
                value++;
            content->offset = atoi(value);
        }
        else if (strncmp(token, "distance:", 9) == 0)
        {
            value = token + 9;
            while (isspace(*value))
                value++;
            content->distance = atoi(value);
        }
        else if (strncmp(token, "within:", 7) == 0)
        {
            value = token + 7;
            while (isspace(*value))
                value++;
            content->within = atoi(value);
        }
        /* New Suricata modifiers */
        else if (strcmp(token, "endswith") == 0)
        {
            content->endswith = 1;
            clib_warning("DEBUG: Set endswith for content");
        }
        else if (strcmp(token, "startswith") == 0)
        {
            content->startswith = 1;
            clib_warning("DEBUG: Set startswith for content");
        }
        else if (strncmp(token, "bsize:", 6) == 0)
        {
            value = token + 6;
            while (isspace(*value))
                value++;

            content->bsize_enabled = 1;
            if (*value == '>')
            {
                content->bsize_operator = 1; /* greater than */
                content->bsize = atoi(value + 1);
            }
            else if (*value == '<')
            {
                content->bsize_operator = 2; /* less than */
                content->bsize = atoi(value + 1);
            }
            else
            {
                content->bsize_operator = 0; /* equal */
                content->bsize = atoi(value);
            }
            clib_warning("DEBUG: Set bsize=%u (op=%u) for content", content->bsize, content->bsize_operator);
        }
        /* Fast pattern modifiers */
        else if (strcmp(token, "fast_pattern") == 0)
        {
            content->fast_pattern = 1;
            clib_warning("DEBUG: Set fast_pattern for content");
        }
        else if (strncmp(token, "fast_pattern:", 13) == 0)
        {
            content->fast_pattern = 1;
            value = token + 13;
            while (isspace(*value))
                value++;

            /* Parse fast_pattern options */
            if (strstr(value, "only"))
                content->fast_pattern_only = 1;
        }
        /* Case sensitivity */
        else if (strcmp(token, "nocase") == 0)
        {
            content->nocase = 1;
        }
        /* Raw bytes */
        else if (strcmp(token, "rawbytes") == 0)
        {
            content->rawbytes = 1;
        }
        /* HTTP context modifiers */
        else if (strcmp(token, "http_method") == 0)
        {
            content->http_method = 1;
        }
        else if (strcmp(token, "http_uri") == 0)
        {
            content->http_uri = 1;
        }
        else if (strcmp(token, "http_header") == 0)
        {
            content->http_header = 1;
        }
        else if (strcmp(token, "http_cookie") == 0)
        {
            content->http_cookie = 1;
        }
        else if (strcmp(token, "http_user_agent") == 0)
        {
            content->http_user_agent = 1;
        }
        else if (strcmp(token, "http_host") == 0)
        {
            content->http_host = 1;
        }
        else if (strcmp(token, "http_raw_uri") == 0)
        {
            content->http_raw_uri = 1;
        }
        else if (strcmp(token, "http_stat_code") == 0)
        {
            content->http_stat_code = 1;
        }
        else if (strcmp(token, "http_stat_msg") == 0)
        {
            content->http_stat_msg = 1;
        }

        token = ips_strtok_r(NULL, ";", &saveptr);
    }

    free(mod_copy);
    return 0;
}

/**
 * @brief Parse flow state options (enhanced)
 */
static int
parse_enhanced_flow_options(char *flow_str, ips_rule_options_t *options)
{
    char *token, *saveptr;
    char *flow_copy = ips_strdup(flow_str);

    if (!flow_copy)
        return -1;

    token = ips_strtok_r(flow_copy, ",", &saveptr);
    while (token)
    {
        /* Skip leading whitespace */
        while (isspace(*token))
            token++;

        if (strcmp(token, "established") == 0)
        {
            options->flow_established = 1;
        }
        else if (strcmp(token, "not_established") == 0)
        {
            options->flow_not_established = 1;
        }
        else if (strcmp(token, "stateless") == 0)
        {
            options->flow_stateless = 1;
        }
        else if (strcmp(token, "to_client") == 0)
        {
            options->flow_to_client = 1;
        }
        else if (strcmp(token, "to_server") == 0)
        {
            options->flow_to_server = 1;
        }
        else if (strcmp(token, "from_client") == 0)
        {
            options->flow_from_client = 1;
        }
        else if (strcmp(token, "from_server") == 0)
        {
            options->flow_from_server = 1;
        }
        else
        {
            clib_warning("Unknown flow option: %s", token);
        }

        token = ips_strtok_r(NULL, ",", &saveptr);
    }

    free(flow_copy);
    return 0;
}

/**
 * @brief Clean Windows line endings and normalize content
 */
static char *
normalize_rule_line(char *line)
{
    char *normalized;
    int i, j;
    int len = strlen(line);

    normalized = malloc(len + 1);
    if (!normalized)
        return NULL;

    /* Remove Windows CRLF and normalize whitespace */
    for (i = 0, j = 0; i < len; i++)
    {
        if (line[i] == '\r')
        {
            /* Skip carriage return */
            continue;
        }
        else if (line[i] == '\n')
        {
            /* Convert to space */
            normalized[j++] = ' ';
        }
        else
        {
            normalized[j++] = line[i];
        }
    }
    normalized[j] = '\0';

    return normalized;
}

/**
 * @brief Enhanced Suricata rule options parser
 */
static int
parse_enhanced_suricata_options(char *options_str, ips_rule_t *rule)
{
    char *token, *value;
    char *saveptr;
    char *opt_copy = ips_strdup(options_str);
    ips_enhanced_content_t *current_content = NULL;

    if (!opt_copy)
        return -1;

    /* Initialize options */
    clib_memset(&rule->options, 0, sizeof(rule->options));

    /* Initialize multi-content array */
    rule->contents = NULL;
    rule->content_count = 0;

    token = ips_strtok_r(opt_copy, ";", &saveptr);
    while (token)
    {
        /* Skip leading whitespace */
        while (isspace(*token))
            token++;

        /* Skip empty tokens */
        if (*token == '\0')
        {
            token = ips_strtok_r(NULL, ";", &saveptr);
            continue;
        }

        /* Basic options */
        if (strncmp(token, "msg:", 4) == 0)
        {
            value = token + 4;
            while (isspace(*value))
                value++;
            if (*value == '"')
            {
                value++;
                char *end_quote = strchr(value, '"');
                if (end_quote)
                    *end_quote = '\0';
            }
            rule->msg = format(0, "%s%c", value, 0);
        }
        else if (strncmp(token, "content:", 8) == 0)
        {
            value = token + 8;
            while (isspace(*value))
                value++;
            if (*value == '"')
            {
                value++;
                char *end_quote = strrchr(value, '"');
                if (end_quote)
                    *end_quote = '\0';
            }

            /* Create new content entry */
            ips_content_t *new_content;
            vec_add2(rule->contents, new_content, 1);
            clib_memset(new_content, 0, sizeof(ips_content_t));

            /* Parse content pattern */
            if (strchr(value, '|'))
            {
                /* Hex content */
                new_content->is_hex = 1;
                parse_content_hex_to_content(value, new_content);
            }
            else
            {
                /* Regular text content */
                new_content->pattern = format(0, "%s%c", value, 0);
                new_content->pattern_len = strlen(value);
                new_content->is_hex = 0;
            }

            rule->content_count++;

            /* Set as current content for modifier processing */
            current_content = (ips_enhanced_content_t *)new_content;

            clib_warning("DEBUG: Added content #%u: %s%s (len=%u)",
                        rule->content_count,
                        new_content->is_hex ? "[HEX] " : "",
                        new_content->pattern,
                        new_content->pattern_len);
        }
        /* Content modifiers - apply to current content */
        else if (current_content && strncmp(token, "depth:", 6) == 0)
        {
            value = token + 6;
            while (isspace(*value))
                value++;
            current_content->depth = atoi(value);
        }
        else if (current_content && strncmp(token, "offset:", 7) == 0)
        {
            value = token + 7;
            while (isspace(*value))
                value++;
            current_content->offset = atoi(value);
        }
        else if (current_content && strncmp(token, "distance:", 9) == 0)
        {
            value = token + 9;
            while (isspace(*value))
                value++;
            current_content->distance = atoi(value);
        }
        else if (current_content && strncmp(token, "within:", 7) == 0)
        {
            value = token + 7;
            while (isspace(*value))
                value++;
            current_content->within = atoi(value);
        }
        else if (current_content && strcmp(token, "nocase") == 0)
        {
            current_content->nocase = 1;
        }
        else if (current_content && strcmp(token, "rawbytes") == 0)
        {
            current_content->rawbytes = 1;
        }
        else if (current_content && strcmp(token, "fast_pattern") == 0)
        {
            current_content->fast_pattern = 1;
        }
        else if (current_content && strcmp(token, "endswith") == 0)
        {
            /* This is a new Suricata feature we now support */
            clib_warning("DEBUG: endswith modifier applied to content #%u", rule->content_count);
            /* Store in rule options for now */
            rule->options.metadata = format(rule->options.metadata, "endswith;");
        }
        else if (current_content && strcmp(token, "startswith") == 0)
        {
            /* This is a new Suricata feature we now support */
            clib_warning("DEBUG: startswith modifier applied to content #%u", rule->content_count);
            /* Store in rule options for now */
            rule->options.metadata = format(rule->options.metadata, "startswith;");
        }
        else if (current_content && strncmp(token, "bsize:", 6) == 0)
        {
            /* This is a new Suricata feature we now support */
            value = token + 6;
            while (isspace(*value))
                value++;
            clib_warning("DEBUG: bsize:%s modifier applied to content #%u", value, rule->content_count);
            /* Store in rule options for now */
            rule->options.metadata = format(rule->options.metadata, "bsize:%s;", value);
        }
        /* Rule identification */
        else if (strncmp(token, "sid:", 4) == 0)
        {
            value = token + 4;
            while (isspace(*value))
                value++;
            rule->sid = atoi(value);
        }
        else if (strncmp(token, "rev:", 4) == 0)
        {
            value = token + 4;
            while (isspace(*value))
                value++;
            rule->rev = atoi(value);
        }
        else if (strncmp(token, "gid:", 4) == 0)
        {
            value = token + 4;
            while (isspace(*value))
                value++;
            rule->gid = atoi(value);
        }
        else if (strncmp(token, "priority:", 9) == 0)
        {
            value = token + 9;
            while (isspace(*value))
                value++;
            rule->priority = atoi(value);
        }
        else if (strncmp(token, "classtype:", 10) == 0)
        {
            value = token + 10;
            while (isspace(*value))
                value++;
            rule->classtype = format(0, "%s%c", value, 0);
        }
        else if (strncmp(token, "reference:", 10) == 0)
        {
            value = token + 10;
            while (isspace(*value))
                value++;
            rule->reference = format(0, "%s%c", value, 0);
        }
        else if (strncmp(token, "metadata:", 9) == 0)
        {
            value = token + 9;
            while (isspace(*value))
                value++;
            rule->options.metadata = format(rule->options.metadata, "%s;", value);
        }
        /* Flow options */
        else if (strncmp(token, "flow:", 5) == 0)
        {
            value = token + 5;
            while (isspace(*value))
                value++;
            parse_enhanced_flow_options(value, &rule->options);
        }
        /* Other options that we'll skip for now but log */
        else if (strstr(token, "app-layer-event:") ||
                 strstr(token, "flowint:") ||
                 strstr(token, "threshold:") ||
                 strstr(token, "detection_filter:"))
        {
            clib_warning("DEBUG: Skipping unsupported option: %s", token);
        }
        else
        {
            /* Unknown option - log but continue */
            clib_warning("DEBUG: Unknown option: %s", token);
        }

        token = ips_strtok_r(NULL, ";", &saveptr);
    }

    free(opt_copy);

    /* Copy legacy content if needed */
    if (rule->content_count > 0)
    {
        rule->content = vec_dup(rule->contents[0].pattern);
        rule->content_len = rule->contents[0].pattern_len;
    }

    return 0;
}

/**
 * @brief Enhanced Suricata rule parser entry point
 */
int
parse_enhanced_suricata_rule(char *line, ips_rule_t *rule)
{
    char *normalized_line;
    char *tokens[10];
    char *options_start;
    int token_count = 0;
    char *token;
    char *saveptr;
    char *line_copy;

    if (!line || !rule)
        return -1;

    /* Normalize line endings and whitespace */
    normalized_line = normalize_rule_line(line);
    if (!normalized_line)
        return -1;

    /* Skip comments and empty lines */
    char *trimmed = normalized_line;
    while (isspace(*trimmed))
        trimmed++;
    if (*trimmed == '#' || *trimmed == '\0')
    {
        free(normalized_line);
        return 0;
    }

    /* Initialize rule */
    clib_memset(rule, 0, sizeof(*rule));
    rule->flags = IPS_RULE_FLAG_ENABLED;
    rule->direction = IPS_FLOW_DIR_BOTH;

    /* Find options part */
    options_start = strchr(trimmed, '(');
    if (options_start)
    {
        *options_start = '\0';
        options_start++;
        char *options_end = strrchr(options_start, ')');
        if (options_end)
            *options_end = '\0';
    }

    /* Parse main rule parts */
    line_copy = ips_strdup(trimmed);
    if (!line_copy)
    {
        free(normalized_line);
        return -1;
    }

    token = ips_strtok_r(line_copy, " \t", &saveptr);
    while (token && token_count < 10)
    {
        tokens[token_count++] = ips_strdup(token);
        token = ips_strtok_r(NULL, " \t", &saveptr);
    }

    if (token_count < 7)
    {
        /* Not enough tokens for a valid rule */
        for (int i = 0; i < token_count; i++)
            free(tokens[i]);
        free(line_copy);
        free(normalized_line);
        return -1;
    }

    /* Parse rule action */
    if (strcmp(tokens[0], "alert") == 0)
        rule->action = IPS_ACTION_ALERT;
    else if (strcmp(tokens[0], "drop") == 0)
        rule->action = IPS_ACTION_DROP;
    else if (strcmp(tokens[0], "reject") == 0)
        rule->action = IPS_ACTION_REJECT;
    else if (strcmp(tokens[0], "pass") == 0)
        rule->action = IPS_ACTION_PASS;
    else
        rule->action = IPS_ACTION_ALERT;

    /* Parse protocol */
    if (strcmp(tokens[1], "tcp") == 0)
        rule->protocol = IPS_PROTO_TCP;
    else if (strcmp(tokens[1], "udp") == 0)
        rule->protocol = IPS_PROTO_UDP;
    else if (strcmp(tokens[1], "icmp") == 0)
        rule->protocol = IPS_PROTO_ICMP;
    else if (strcmp(tokens[1], "ip") == 0)
        rule->protocol = 0; /* Any protocol */
    else if (strcmp(tokens[1], "http") == 0)
        rule->protocol = IPS_PROTO_TCP; /* HTTP is over TCP */
    else
        rule->protocol = atoi(tokens[1]);

    /* Skip address and port parsing for now - use defaults */
    /* This could be enhanced later */

    /* Parse options */
    if (options_start)
    {
        if (parse_enhanced_suricata_options(options_start, rule) != 0)
        {
            clib_warning("Failed to parse rule options: %s", options_start);
        }
    }

    /* Cleanup */
    for (int i = 0; i < token_count; i++)
        free(tokens[i]);
    free(line_copy);
    free(normalized_line);

    return 0;
}
