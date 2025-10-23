/*
 * Copyright (c) 2023 VPP IPS Multi-Content Support
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <ctype.h>
#include "ips.h"

/* Multi-Content Support Functions */

/**
 * @brief Parse mixed ASCII and hex content string into ips_content_t structure
 * Supports mixed content like "uid=0|28|root|29|" -> uid=0\x1croot\x1d
 */
int
parse_content_hex_to_content (char *content_str, ips_content_t *content)
{
    if (!content_str || !content)
    {
        clib_warning ("Invalid parameters for hex content parsing");
        return -1;
    }

    u8 *pattern = NULL;
    size_t len = strlen (content_str);
    size_t i = 0;

    while (i < len)
    {
        if (content_str[i] == '|')
        {
            /* Enter HEX mode */
            i++; /* Skip opening '|' */
            while (i < len && content_str[i] != '|')
            {
                /* Skip whitespace */
                while (i < len && isspace (content_str[i]))
                    i++;

                if (i + 1 < len && isxdigit (content_str[i]) && isxdigit (content_str[i + 1]))
                {
                    char hex_byte[3] = {content_str[i], content_str[i + 1], 0};
                    u8 byte_val = (u8) strtol (hex_byte, NULL, 16);
                    vec_add1 (pattern, byte_val);
                    i += 2;
                }
                else if (i < len && content_str[i] != '|')
                {
                    /* Invalid hex character, skip */
                    clib_warning ("Invalid hex character '%c' in content: %s", content_str[i], content_str);
                    i++;
                }
            }
            /* Skip closing '|' */
            if (i < len && content_str[i] == '|')
                i++;
        }
        else
        {
            /* Regular ASCII character */
            vec_add1 (pattern, (u8) content_str[i]);
            i++;
        }
    }

    if (vec_len (pattern) == 0)
    {
        clib_warning ("No valid content parsed from: %s", content_str);
        if (pattern)
            vec_free (pattern);
        return -1;
    }

    content->pattern = pattern;
    content->pattern_len = vec_len (pattern);
    content->is_hex = 1; /* Mark as hex to indicate binary content */

    clib_warning ("DEBUG: Successfully parsed %u bytes from mixed content: %s",
                 content->pattern_len, content_str);

    /* Debug: Print parsed bytes */
    if (content->pattern_len <= 32) /* Limit debug output */
    {
        char debug_str[256] = {0};
        char *debug_ptr = debug_str;
        for (u32 j = 0; j < content->pattern_len && j < 32; j++)
        {
            if (isprint (content->pattern[j]))
                debug_ptr += sprintf (debug_ptr, "%c", content->pattern[j]);
            else
                debug_ptr += sprintf (debug_ptr, "\\x%02x", content->pattern[j]);
        }
        clib_warning ("DEBUG: Parsed pattern: %s", debug_str);
    }

    return 0;
}

/**
 * @brief Add content pattern to rule (multi-content support)
 */
int
ips_rule_add_content (ips_rule_t *rule, const char *pattern, u32 pattern_len, u8 is_hex)
{
    if (!rule || !pattern)
        return -1;

    /* Allocate new content entry */
    vec_validate (rule->contents, rule->content_count);
    ips_content_t *content = &rule->contents[rule->content_count];
    clib_memset (content, 0, sizeof (ips_content_t));

    /* Set pattern */
    content->pattern = vec_new (u8, pattern_len);
    memcpy (content->pattern, pattern, pattern_len);
    content->pattern_len = pattern_len;
    content->is_hex = is_hex;

    rule->content_count++;

    /* Legacy support: Set first content as primary */
    if (rule->content_count == 1)
    {
        if (is_hex)
        {
            rule->content_hex = vec_dup (content->pattern);
            rule->content_hex_len = content->pattern_len;
        }
        else
        {
            rule->content = vec_dup (content->pattern);
            rule->content_len = content->pattern_len;
        }
    }

    return 0;
}

/**
 * @brief Apply content modifiers to the last added content
 */
int
ips_rule_set_content_modifiers (ips_rule_t *rule, u32 depth, u32 offset,
                                u32 distance, u32 within, u8 nocase, u8 rawbytes)
{
    if (!rule || rule->content_count == 0)
        return -1;

    ips_content_t *content = &rule->contents[rule->content_count - 1];

    content->depth = depth;
    content->offset = offset;
    content->distance = distance;
    content->within = within;
    content->nocase = nocase;
    content->rawbytes = rawbytes;

    return 0;
}

/**
 * @brief Check if rule has any content patterns
 */
u8
ips_rule_has_content (ips_rule_t *rule)
{
    if (!rule)
        return 0;

    return (rule->content_count > 0) || (rule->content != NULL) || (rule->content_hex != NULL);
}

/**
 * @brief Get content count for rule
 */
u32
ips_rule_get_content_count (ips_rule_t *rule)
{
    if (!rule)
        return 0;

    return rule->content_count;
}

/**
 * @brief Get specific content pattern from rule
 */
ips_content_t *
ips_rule_get_content (ips_rule_t *rule, u32 index)
{
    if (!rule || index >= rule->content_count)
        return NULL;

    return &rule->contents[index];
}

/**
 * @brief Debug print all content patterns in rule
 */
void
ips_rule_debug_print_contents (ips_rule_t *rule)
{
    if (!rule)
        return;

    clib_warning ("Rule SID:%u has %u content patterns:", rule->sid, rule->content_count);

    for (u32 i = 0; i < rule->content_count; i++)
    {
        ips_content_t *content = &rule->contents[i];
        if (content->is_hex)
        {
            clib_warning ("  Content[%u]: [HEX] len=%u depth=%u offset=%u distance=%u within=%u",
                         i, content->pattern_len, content->depth, content->offset,
                         content->distance, content->within);
        }
        else
        {
            clib_warning ("  Content[%u]: '%s' len=%u depth=%u offset=%u distance=%u within=%u%s%s",
                         i, content->pattern, content->pattern_len, content->depth, content->offset,
                         content->distance, content->within,
                         content->nocase ? " nocase" : "",
                         content->rawbytes ? " rawbytes" : "");
        }
    }

    /* Legacy content */
    if (rule->content)
    {
        clib_warning ("  Legacy content: '%s' len=%u", rule->content, rule->content_len);
    }
    if (rule->content_hex)
    {
        clib_warning ("  Legacy hex content: [HEX] len=%u", rule->content_hex_len);
    }
}
