/*
 * ips_rule_parser.c - VPP IPS Plugin Rule Parser
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <vppinfra/string.h>

/* Explicit C99 function declarations */
size_t strlen(const char *s);
void *memcpy(void *dest, const void *src, size_t n);
int memcmp(const void *s1, const void *s2, size_t n);
size_t strspn(const char *s, const char *accept);
char *strpbrk(const char *s, const char *accept);
int strncmp(const char *s1, const char *s2, size_t n);
char *strchr(const char *s, int c);
char *strrchr(const char *s, int c);
int strcmp(const char *s1, const char *s2);
size_t strcspn(const char *s, const char *reject);
int atoi(const char *nptr);
void *malloc(size_t size);
void free(void *ptr);
/* Note: isspace is a macro, not a function, so no declaration needed */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

#include "ips.h"
#include "rules/ips_rule_parser.h"

/* External function declaration for advanced parser */
extern int parse_advanced_rule_line (char *line, ips_rule_t *rule);

/* C99 compatible strdup implementation */
char *
ips_strdup (const char *s)
{
  size_t len = strlen (s) + 1;
  char *dup = malloc (len);
  if (dup)
    {
      memcpy (dup, s, len);
    }
  return dup;
}

/* C99 compatible strtok_r implementation */
char *
ips_strtok_r (char *str, const char *delim, char **saveptr)
{
  char *token;

  if (str == NULL)
    str = *saveptr;

  /* Skip leading delimiters */
  str += strspn (str, delim);
  if (*str == '\0')
    {
      *saveptr = str;
      return NULL;
    }

  /* Find end of token */
  token = str;
  str = strpbrk (token, delim);
  if (str == NULL)
    {
      /* This token extends to end of string */
      *saveptr = token + strlen (token);
    }
  else
    {
      /* Terminate token and set up for next call */
      *str = '\0';
      *saveptr = str + 1;
    }

  return token;
}

/**
 * @brief Parse rule action
 */
static ips_action_t
parse_action (char *action_str)
{
  if (clib_strcmp (action_str, "drop") == 0)
    return IPS_ACTION_DROP;
  else if (clib_strcmp (action_str, "alert") == 0)
    return IPS_ACTION_ALERT;
  else if (clib_strcmp (action_str, "reject") == 0)
    return IPS_ACTION_REJECT;
  else if (clib_strcmp (action_str, "pass") == 0)
    return IPS_ACTION_PASS;
  else if (clib_strcmp (action_str, "log") == 0)
    return IPS_ACTION_LOG;
  else
    return IPS_ACTION_PASS;
}

/**
 * @brief Parse protocol
 */
static u8
parse_protocol (char *proto_str)
{
  if (clib_strcmp (proto_str, "tcp") == 0)
    return IPS_PROTO_TCP;
  else if (clib_strcmp (proto_str, "udp") == 0)
    return IPS_PROTO_UDP;
  else if (clib_strcmp (proto_str, "icmp") == 0)
    return IPS_PROTO_ICMP;
  else if (clib_strcmp (proto_str, "ip") == 0)
    return 0; /* Any protocol */
  else
    return 0;
}

/**
 * @brief Parse address/CIDR
 */
static int
parse_address (char *addr_str, void *addr_union, u8 *prefix_len, u8 *is_ip6)
{
    char *slash_pos;
    char addr_part[256];
    int ret;

    *is_ip6 = 0;
    *prefix_len = 0;

    if (clib_strcmp (addr_str, "any") == 0)
    {
        clib_memset (addr_union, 0, sizeof (ip4_address_t) > sizeof (ip6_address_t) ? sizeof (ip6_address_t) : sizeof (ip4_address_t));
        *prefix_len = 0;
        return 0;
    }

    /* Check for CIDR notation */
    /* Find slash for CIDR notation */
    u32 i;
    slash_pos = NULL;
    for (i = 0; addr_str[i]; i++)
    {
        if (addr_str[i] == '/')
        {
            slash_pos = &addr_str[i];
            break;
        }
    }

    if (slash_pos)
    {
        clib_memcpy (addr_part, addr_str, slash_pos - addr_str);
        addr_part[slash_pos - addr_str] = '\0';
        *prefix_len = atoi (slash_pos + 1);
    }
    else
    {
        /* Copy entire string */
        u32 len = 0;
        while (addr_str[len]) len++; /* Calculate length manually */
        clib_memcpy (addr_part, addr_str, len + 1);
        *prefix_len = 32; /* Default to /32 for IPv4 */
    }

    /* Try IPv4 first */
    ret = inet_pton (AF_INET, addr_part, addr_union);
    if (ret == 1)
    {
        *is_ip6 = 0;
        if (!slash_pos)
            *prefix_len = 32;
        return 0;
    }

    /* Try IPv6 */
    ret = inet_pton (AF_INET6, addr_part, addr_union);
    if (ret == 1)
    {
        *is_ip6 = 1;
        if (!slash_pos)
            *prefix_len = 128;
        return 0;
    }

    return -1; /* Invalid address */
}

/**
 * @brief Parse port range
 */
static int
parse_port_range (char *port_str, u16 *min_port, u16 *max_port)
{
    char *colon_pos;

    if (clib_strcmp (port_str, "any") == 0)
    {
        *min_port = 0;
        *max_port = 65535;
        return 0;
    }

    /* Find colon for port range */
    colon_pos = NULL;
    for (u32 i = 0; port_str[i]; i++)
    {
        if (port_str[i] == ':')
        {
            colon_pos = &port_str[i];
            break;
        }
    }
    if (colon_pos)
    {
        *colon_pos = '\0';
        *min_port = atoi (port_str);
        *max_port = atoi (colon_pos + 1);
    }
    else
    {
        *min_port = *max_port = atoi (port_str);
    }

    return 0;
}

/**
 * @brief Parse rule options
 */
static int
parse_rule_options (char *options_str, ips_rule_t *rule)
{
    char *token, *value;
    char *saveptr;
    char *opt_copy;

    if (!options_str || !rule)
        return -1;

      opt_copy = ips_strdup (options_str);
  if (!opt_copy)
    return -1;

  token = ips_strtok_r (opt_copy, ";", &saveptr);
    while (token)
    {
        /* Skip leading whitespace */
        while (isspace (*token))
            token++;

        if (strncmp (token, "msg:", 4) == 0)
        {
            value = token + 4;
            while (isspace (*value))
                value++;
            if (*value == '"')
            {
                value++;
                char *end_quote = strchr (value, '"');
                if (end_quote)
                    *end_quote = '\0';
            }
            rule->msg = format (0, "%s%c", value, 0);
        }
        else if (strncmp (token, "content:", 8) == 0)
        {
            value = token + 8;
            while (isspace (*value))
                value++;
            if (*value == '"')
            {
                value++;
                char *end_quote = strchr (value, '"');
                if (end_quote)
                    *end_quote = '\0';
            }
            rule->content = format (0, "%s%c", value, 0);
            rule->content_len = strlen (value);
        }
        else if (strncmp (token, "sid:", 4) == 0)
        {
            value = token + 4;
            while (isspace (*value))
                value++;
            rule->sid = atoi (value);
        }
        else if (strncmp (token, "gid:", 4) == 0)
        {
            value = token + 4;
            while (isspace (*value))
                value++;
            rule->gid = atoi (value);
        }
        else if (strncmp (token, "priority:", 9) == 0)
        {
            value = token + 9;
            while (isspace (*value))
                value++;
            rule->priority = atoi (value);
        }
        else if (strncmp (token, "classtype:", 10) == 0)
        {
            value = token + 10;
            while (isspace (*value))
                value++;
            rule->classtype = format (0, "%s%c", value, 0);
        }
        else if (strncmp (token, "reference:", 10) == 0)
        {
            value = token + 10;
            while (isspace (*value))
                value++;
            rule->reference = format (0, "%s%c", value, 0);
        }
        else if (strcmp (token, "nocase") == 0)
        {
            rule->flags |= IPS_RULE_FLAG_NOCASE;
        }
        /* Skip unsupported Suricata-specific options to prevent false positives */
        else if (strncmp (token, "stream-event:", 13) == 0)
        {
            /* Mark rule as unsupported - will be filtered out later */
            rule->flags |= IPS_RULE_FLAG_UNSUPPORTED;
        }
        else if (strncmp (token, "flowbits:", 9) == 0)
        {
            /* Mark rule as unsupported - will be filtered out later */
            rule->flags |= IPS_RULE_FLAG_UNSUPPORTED;
        }
        else if (strncmp (token, "flowint:", 8) == 0)
        {
            /* Mark rule as unsupported - will be filtered out later */
            rule->flags |= IPS_RULE_FLAG_UNSUPPORTED;
        }
        else if (strncmp (token, "decode-event:", 13) == 0)
        {
            /* Mark rule as unsupported - will be filtered out later */
            rule->flags |= IPS_RULE_FLAG_UNSUPPORTED;
        }
        else if (strncmp (token, "app-layer-event:", 16) == 0)
        {
            /* Mark rule as unsupported - will be filtered out later */
            rule->flags |= IPS_RULE_FLAG_UNSUPPORTED;
        }
        else if (strncmp (token, "ipv4-csum:", 10) == 0)
        {
            /* Mark rule as unsupported - will be filtered out later */
            rule->flags |= IPS_RULE_FLAG_UNSUPPORTED;
        }
        else if (strncmp (token, "tcpv4-csum:", 11) == 0)
        {
            /* Mark rule as unsupported - will be filtered out later */
            rule->flags |= IPS_RULE_FLAG_UNSUPPORTED;
        }
        else if (strncmp (token, "tcpv6-csum:", 11) == 0)
        {
            /* Mark rule as unsupported - will be filtered out later */
            rule->flags |= IPS_RULE_FLAG_UNSUPPORTED;
        }
        else if (strncmp (token, "flow:", 5) == 0)
        {
            /* Mark rule as unsupported - will be filtered out later */
            rule->flags |= IPS_RULE_FLAG_UNSUPPORTED;
        }
        else if (strcmp (token, "noalert") == 0)
        {
            /* Mark rule as unsupported - will be filtered out later */
            rule->flags |= IPS_RULE_FLAG_UNSUPPORTED;
        }

        token = ips_strtok_r (NULL, ";", &saveptr);
    }

    free (opt_copy);
    return 0;
}

/**
 * @brief Parse a single rule line
 */
static int
parse_rule_line (char *line, ips_rule_t *rule)
{
    char *tokens[10];
    char *options_start;
    int token_count = 0;
    char *token;
    char *saveptr;
    char *line_copy;

    if (!line || !rule)
        return -1;

    /* Skip comments and empty lines */
    while (isspace (*line))
        line++;
    if (*line == '#' || *line == '\0')
        return 0;

    /* Initialize rule */
    clib_memset (rule, 0, sizeof (*rule));
    rule->flags = IPS_RULE_FLAG_ENABLED;
    rule->direction = IPS_FLOW_DIR_BOTH;

    /* Find options part */
    options_start = strchr (line, '(');
    if (options_start)
    {
        *options_start = '\0';
        options_start++;
        char *options_end = strrchr (options_start, ')');
        if (options_end)
            *options_end = '\0';
    }

    /* Parse main rule parts */
          line_copy = ips_strdup (line);
      if (!line_copy)
        return -1;

      token = ips_strtok_r (line_copy, " \t", &saveptr);
      while (token && token_count < 10)
      {
        tokens[token_count++] = ips_strdup (token);
        token = ips_strtok_r (NULL, " \t", &saveptr);
    }

    if (token_count < 7)
    {
        /* Not enough tokens for a valid rule */
        for (int i = 0; i < token_count; i++)
            free (tokens[i]);
        free (line_copy);
        return -1;
    }

    /* Parse rule components */
    rule->action = parse_action (tokens[0]);
    rule->protocol = parse_protocol (tokens[1]);

    /* Parse source address and port */
    u8 src_is_ip6;
    parse_address (tokens[2], &rule->src_addr, &rule->src_addr_mask, &src_is_ip6);
    parse_port_range (tokens[3], &rule->src_port_min, &rule->src_port_max);

    /* Parse direction */
    if (strcmp (tokens[4], "->") == 0)
        rule->direction = IPS_FLOW_DIR_TO_SERVER;
    else if (strcmp (tokens[4], "<-") == 0)
        rule->direction = IPS_FLOW_DIR_TO_CLIENT;
    else
        rule->direction = IPS_FLOW_DIR_BOTH;

    /* Parse destination address and port */
    u8 dst_is_ip6;
    parse_address (tokens[5], &rule->dst_addr, &rule->dst_addr_mask, &dst_is_ip6);
    parse_port_range (tokens[6], &rule->dst_port_min, &rule->dst_port_max);

    /* Parse options */
    if (options_start)
    {
        parse_rule_options (options_start, rule);
    }

    /* Generate rule ID if not specified */
    if (rule->sid == 0)
    {
        static u32 auto_rule_id = 1000000;
        rule->rule_id = auto_rule_id++;
        rule->sid = rule->rule_id;
    }
    else
    {
        rule->rule_id = rule->sid;
    }

    /* Cleanup */
    for (int i = 0; i < token_count; i++)
        free (tokens[i]);
    free (line_copy);

    return 1; /* Successfully parsed */
}

/**
 * @brief Enhanced rule loading function that supports both simple and advanced rules
 */
int
ips_load_rules_from_file_enhanced (const char *filename)
{
    FILE *file;
    char line[4096];
    ips_rule_t rule;
    int rules_loaded = 0;
    int line_number = 0;
    int advanced_rules_count = 0;
    int basic_rules_count = 0;
    int skipped_rules_count = 0;

    file = fopen (filename, "r");
    if (!file)
    {
        clib_warning ("Failed to open rules file: %s", filename);
        return -1;
    }

    clib_warning ("Loading rules from: %s (Enhanced Parser)", filename);

    char complete_rule[16384] = "";  /* Buffer for complete multi-line rule */
    int in_rule = 0;  /* Flag to track if we're inside a rule */

    while (fgets (line, sizeof (line), file))
    {
        line_number++;

        /* Remove newline */
        line[strcspn (line, "\n")] = '\0';

        /* Skip comments and empty lines */
        char *trimmed = line;
        while (isspace (*trimmed))
            trimmed++;
        if (*trimmed == '\0' || *trimmed == '#')
            continue;

        /* Check if this line starts a new rule */
        if (!in_rule && (strncmp(trimmed, "alert", 5) == 0 ||
                         strncmp(trimmed, "drop", 4) == 0 ||
                         strncmp(trimmed, "reject", 6) == 0 ||
                         strncmp(trimmed, "pass", 4) == 0 ||
                         strncmp(trimmed, "log", 3) == 0))
        {
            /* Start of a new rule */
            in_rule = 1;
            strcpy(complete_rule, trimmed);

            /* For multi-line rules, we should always continue reading until we find ')' */
            char *open_paren = strchr(trimmed, '(');
            char *comment_start = strchr(trimmed, '#');
            char *close_paren = NULL;

            if (comment_start) {
                /* Only look for closing paren before comment */
                char temp = *comment_start;
                *comment_start = '\0';
                close_paren = strchr(trimmed, ')');
                *comment_start = temp;
            } else {
                close_paren = strchr(trimmed, ')');
            }

            if (open_paren && close_paren)
            {
                /* Single-line rule (rare), process immediately */
                in_rule = 0;
                trimmed = complete_rule;
                clib_warning ("DEBUG: Single-line rule found: %.100s...", complete_rule);
            }
            else if (open_paren)
            {
                /* Multi-line rule started, continue reading */
                clib_warning ("DEBUG: Multi-line rule started: %s", trimmed);
                continue;
            }
            else
            {
                /* Malformed rule - no opening parenthesis */
                clib_warning ("Malformed rule at line %d: %s", line_number, trimmed);
                in_rule = 0;
                complete_rule[0] = '\0';
                continue;
            }
        }
        else if (in_rule)
        {
            /* We're inside a rule, append this line with proper space handling */
            size_t current_len = strlen(complete_rule);
            size_t trimmed_len = strlen(trimmed);

            if (current_len + trimmed_len + 2 < sizeof(complete_rule))
            {
                strcat(complete_rule, " ");
                strcat(complete_rule, trimmed);

                /* Debug: show what we're appending */
                clib_warning ("DEBUG: Appending to rule (line %d): %s", line_number, trimmed);
            }
            else
            {
                clib_warning ("Rule too long at line %d (current: %lu, adding: %lu), truncating",
                             line_number, (unsigned long)current_len, (unsigned long)trimmed_len);
                in_rule = 0;
                complete_rule[0] = '\0';
                continue;
            }

            /* Check if this line contains the closing parenthesis (ignore parentheses in comments) */
            char *comment_start = strchr(trimmed, '#');
            char *close_paren = NULL;
            if (comment_start) {
                /* Only look for closing paren before comment */
                char temp = *comment_start;
                *comment_start = '\0';
                close_paren = strchr(trimmed, ')');
                *comment_start = temp;
            } else {
                close_paren = strchr(trimmed, ')');
            }

            if (close_paren)
            {
                /* Rule is complete, process it */
                in_rule = 0;
                trimmed = complete_rule;

                /* Debug: print the complete rule length and preview */
                clib_warning ("DEBUG: Complete rule (%lu chars): %.200s...",
                             (unsigned long)strlen(complete_rule), complete_rule);
            }
            else
            {
                /* Still building the rule, continue */
                continue;
            }
        }
        else
        {
            /* Line outside of rule - skip it */
            clib_warning ("Skipping line outside rule at line %d: %s", line_number, trimmed);
            continue;
        }

        /* Check for unsupported features and warn */
        int has_unsupported = 0;
        if (strstr (trimmed, "flowbits:") || strstr (trimmed, "http_method") ||
            strstr (trimmed, "http_host") || strstr (trimmed, "http_uri") ||
            strstr (trimmed, "http_user_agent") || strstr (trimmed, "http_cookie") ||
            strstr (trimmed, "luajit:") ||
            strstr (trimmed, "xbits:") || strstr (trimmed, "stream_size:") ||
            strstr (trimmed, "base64_decode") || strstr (trimmed, "urilen:") ||
            strstr (trimmed, "stream-event:") || strstr (trimmed, "flowint:") ||
            strstr (trimmed, "decode-event:") || strstr (trimmed, "app-layer-event:") ||
            strstr (trimmed, "noalert") || strstr (trimmed, "pkthdr") ||
            strstr (trimmed, "ipv4-csum:") || strstr (trimmed, "tcpv4-csum:") ||
            strstr (trimmed, "tcpv6-csum:") || strstr (trimmed, "flow:") ||
            strstr (trimmed, "msg:\"SURICATA"))
        {
            has_unsupported = 1;
            clib_warning ("Rule at line %d contains unsupported features, skipping: %s",
                         line_number, trimmed);
            skipped_rules_count++;
            continue;
        }

        /* Detect if rule uses advanced features */
        int is_advanced_rule = 0;
        if (strstr (trimmed, "flags:") || strstr (trimmed, "ttl:") ||
            strstr (trimmed, "tos:") || strstr (trimmed, "seq:") ||
            strstr (trimmed, "ack:") || strstr (trimmed, "flow:") ||
            strstr (trimmed, "dsize:") || strstr (trimmed, "byte_test:") ||
            strstr (trimmed, "threshold:") || strstr (trimmed, "depth:") ||
            strstr (trimmed, "offset:") || strstr (trimmed, "distance:") ||
            strstr (trimmed, "within:") || strstr (trimmed, "itype:") ||
            strstr (trimmed, "icode:") || strstr (trimmed, "isdataat:") ||
            strstr (trimmed, "fast_pattern") || strstr (trimmed, "byte_jump:") ||
            strstr (trimmed, "byte_extract:") || strstr (trimmed, "pcre:"))
        {
            is_advanced_rule = 1;
        }

        clib_memset (&rule, 0, sizeof (rule));

        int parse_success = 0;

        if (is_advanced_rule)
        {
            /* Try advanced parser */
            int result = parse_advanced_rule_line (trimmed, &rule);
            if (result == 0)
            {
                advanced_rules_count++;
                parse_success = 1;
            }
        }
        else
        {
            /* Try basic parser first */
            int result = parse_rule_line (trimmed, &rule);
            if (result > 0)  /* Basic parser returns > 0 for success */
            {
                basic_rules_count++;
                parse_success = 1;
            }
            else
            {
                /* If basic parser fails, try advanced parser as fallback */
                clib_memset (&rule, 0, sizeof (rule));
                result = parse_advanced_rule_line (trimmed, &rule);
                if (result == 0)  /* Advanced parser returns 0 for success */
                {
                    advanced_rules_count++;
                    parse_success = 1;
                }
            }
        }

        if (parse_success)
        {
            /* Validate rule before adding */
            if (rule.sid == 0)
            {
                clib_warning ("Rule at line %d has invalid SID, skipping", line_number);
                /* Free allocated memory */
                vec_free (rule.msg);
                vec_free (rule.reference);
                vec_free (rule.classtype);
                vec_free (rule.content);
                if (rule.content_hex)
                    free (rule.content_hex);
                continue;
            }

            /* Validate content for Hyperscan compatibility */
            if (rule.content)
            {
                char *content_str = (char *) rule.content;
                /* Check for problematic patterns that cause "Embedded end anchors" error */
                if (strstr(content_str, "$") || strstr(content_str, "^") ||
                    strstr(content_str, "\\z") || strstr(content_str, "\\Z") ||
                    strstr(content_str, "(?") || strstr(content_str, "[0-9]") ||
                    strstr(content_str, "{") || strstr(content_str, "}") ||
                    strstr(content_str, "\\b") || strstr(content_str, "\\B"))
                {
                    clib_warning ("Rule SID:%u at line %d contains unsupported regex patterns, skipping: %s",
                                 rule.sid, line_number, content_str);
                    /* Free allocated memory */
                    vec_free (rule.msg);
                    vec_free (rule.reference);
                    vec_free (rule.classtype);
                    vec_free (rule.content);
                    if (rule.content_hex)
                        free (rule.content_hex);
                    continue;
                }
            }

            clib_warning ("Attempting to add rule SID:%u - %s",
                         rule.sid, rule.msg ? (char *) rule.msg : "No message");

            /* Add rule to IPS */
            if (ips_rule_add (&rule) == 0)
            {
                rules_loaded++;
                clib_warning ("Successfully loaded rule SID:%u - %s",
                             rule.sid, rule.msg ? (char *) rule.msg : "No message");
            }
            else
            {
                clib_warning ("Failed to add rule SID:%u at line %d to IPS engine", rule.sid, line_number);
                /* Free allocated memory */
                vec_free (rule.msg);
                vec_free (rule.reference);
                vec_free (rule.classtype);
                vec_free (rule.content);
                if (rule.content_hex)
                    free (rule.content_hex);
            }
        }
        else
        {
            clib_warning ("Failed to parse rule at line %d: %s", line_number, trimmed);
        }
    }

    fclose (file);

    clib_warning ("Loaded %d rules from %s (%d basic, %d advanced, %d skipped)",
                 rules_loaded, filename, basic_rules_count, advanced_rules_count,
                 skipped_rules_count);
    return rules_loaded;
}

/**
 * @brief Clear all rules from the system
 */
void
ips_rules_clear (void)
{
    ips_main_t *im = &ips_main;

    /* Free all rule memory */
    if (im->rules)
    {
        vec_free (im->rules);
        im->rules = NULL;
    }

    /* Reset rule counters */
    im->rule_count = 0;
    im->rules_compiled = 0;
    im->rules_dirty = 1;

    clib_warning ("All rules cleared from system");
}
