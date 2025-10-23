/*
 * Copyright (c) 2023 VPP IPS Enhanced Multi-Content Parser
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

/* External string utility functions from existing parser */
extern char *ips_strdup (const char *s);
extern char *ips_strtok_r (char *str, const char *delim, char **saveptr);

/* Enhanced parser with multi-content support */

/**
 * @brief Parse rule options with multi-content support
 */
static int
parse_multi_content_rule_options (char *options_str, ips_rule_t *rule)
{
  char *token, *value;
  char *saveptr;
  char *opt_copy = ips_strdup (options_str);
  ips_content_t *current_content = NULL;  /* Track current content being parsed */

  if (!opt_copy)
    return -1;

  /* Initialize options */
  clib_memset (&rule->options, 0, sizeof (rule->options));

  /* Initialize multi-content array */
  rule->contents = NULL;
  rule->content_count = 0;

  token = ips_strtok_r (opt_copy, ";", &saveptr);
  while (token)
  {
    /* Skip leading whitespace */
    while (isspace (*token))
      token++;

    /* Basic options */
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
      clib_warning ("DEBUG: Parsed MSG='%s'", (char*)rule->msg);
    }
    else if (strncmp (token, "content:", 8) == 0)
    {
      value = token + 8;
      while (isspace (*value))
        value++;
      if (*value == '"')
      {
        value++;
        char *end_quote = strrchr (value, '"');
        if (end_quote)
          *end_quote = '\0';
      }

      /* Check for empty content - skip if empty */
      if (!value || strlen(value) == 0)
      {
        clib_warning ("WARNING: Skipping empty content field in rule options");
        token = ips_strtok_r (NULL, ";", &saveptr);
        continue;
      }

      /* NEW: Multi-content support */
      /* Allocate new content entry */
      vec_validate (rule->contents, rule->content_count);
      current_content = &rule->contents[rule->content_count];
      clib_memset (current_content, 0, sizeof (ips_content_t));

      /* Check for hex content */
      if (strchr (value, '|'))
      {
        /* Parse hex content into new structure */
        current_content->is_hex = 1;
        if (parse_content_hex_to_content (value, current_content) != 0)
        {
          clib_warning ("Failed to parse hex content: %s", value);
          free (opt_copy);
          return -1;
        }

        /* Skip if hex parsing resulted in empty pattern */
        if (current_content->pattern_len == 0)
        {
          clib_warning ("WARNING: Hex parsing resulted in empty pattern, skipping");
          token = ips_strtok_r (NULL, ";", &saveptr);
          continue;
        }

        /* Legacy support: Set first hex content as primary */
        if (rule->content_count == 0)
        {
          rule->content_hex = vec_dup (current_content->pattern);
          rule->content_hex_len = current_content->pattern_len;
        }
      }
      else
      {
        /* Regular text content */
        current_content->pattern = format (0, "%s%c", value, 0);
        current_content->pattern_len = strlen (value);
        current_content->is_hex = 0;

        /* Legacy support: Set first content as primary */
        if (rule->content_count == 0)
        {
          rule->content = vec_dup (current_content->pattern);
          rule->content_len = current_content->pattern_len;
        }
      }

      rule->content_count++;

      clib_warning ("DEBUG: Added content #%u: %s%s (len=%u)",
                   rule->content_count,
                   current_content->is_hex ? "[HEX] " : "",
                   current_content->pattern,
                   current_content->pattern_len);
    }
    /* Content modifiers - apply to current content */
    else if (strncmp (token, "depth:", 6) == 0 && current_content)
    {
      value = token + 6;
      while (isspace (*value))
        value++;
      current_content->depth = atoi (value);
      rule->options.depth = current_content->depth; /* Legacy support */
      clib_warning ("DEBUG: Set depth=%u for content #%u", current_content->depth, rule->content_count);
    }
    else if (strncmp (token, "offset:", 7) == 0 && current_content)
    {
      value = token + 7;
      while (isspace (*value))
        value++;
      current_content->offset = atoi (value);
      rule->options.offset = current_content->offset; /* Legacy support */
      clib_warning ("DEBUG: Set offset=%u for content #%u", current_content->offset, rule->content_count);
    }
    else if (strncmp (token, "distance:", 9) == 0 && current_content)
    {
      value = token + 9;
      while (isspace (*value))
        value++;
      current_content->distance = atoi (value);
      rule->options.distance = current_content->distance; /* Legacy support */
      clib_warning ("DEBUG: Set distance=%u for content #%u", current_content->distance, rule->content_count);
    }
    else if (strncmp (token, "within:", 7) == 0 && current_content)
    {
      value = token + 7;
      while (isspace (*value))
        value++;
      current_content->within = atoi (value);
      rule->options.within = current_content->within; /* Legacy support */
      clib_warning ("DEBUG: Set within=%u for content #%u", current_content->within, rule->content_count);
    }
    else if (strcmp (token, "nocase") == 0 && current_content)
    {
      current_content->nocase = 1;
      rule->options.nocase = 1; /* Legacy support */
      clib_warning ("DEBUG: Set nocase for content #%u", rule->content_count);
    }
    else if (strcmp (token, "rawbytes") == 0 && current_content)
    {
      current_content->rawbytes = 1;
      rule->options.rawbytes = 1; /* Legacy support */
      clib_warning ("DEBUG: Set rawbytes for content #%u", rule->content_count);
    }
    else if (strcmp (token, "fast_pattern") == 0 && current_content)
    {
      current_content->fast_pattern = 1;
      clib_warning ("DEBUG: Set fast_pattern for content #%u", rule->content_count);
    }
    else if (strncmp (token, "sid:", 4) == 0)
    {
      value = token + 4;
      while (isspace (*value))
        value++;
      rule->sid = atoi (value);
      clib_warning ("DEBUG: Parsed SID=%u", rule->sid);
    }
    else if (strncmp (token, "rev:", 4) == 0)
    {
      value = token + 4;
      while (isspace (*value))
        value++;
      rule->rev = atoi (value);
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

    token = ips_strtok_r (NULL, ";", &saveptr);
  }

  free (opt_copy);

  /* Debug print all contents */
  if (rule->content_count > 0)
  {
    ips_rule_debug_print_contents (rule);
  }

  return 0;
}

/**
 * @brief Enhanced rule parser with multi-content support
 */
int
parse_enhanced_multi_content_rule_line (char *line, ips_rule_t *rule)
{
  char *action_str, *protocol_str, *src_addr_str, *src_port_str;
  char *direction_str, *dst_addr_str, *dst_port_str, *options_start;
  char *saveptr;
  char *line_copy = ips_strdup (line);

  if (!line_copy)
    return -1;

  /* Initialize rule */
  clib_memset (rule, 0, sizeof (*rule));

  /* Set defaults */
  rule->sid = 1000000; /* Default SID if not specified */
  rule->gid = 1;
  rule->rev = 1;
  rule->priority = 3;

  /* Parse action */
  action_str = ips_strtok_r (line_copy, " \t", &saveptr);
  if (!action_str)
  {
    free (line_copy);
    return -1;
  }

  if (strcmp (action_str, "alert") == 0)
    rule->action = IPS_ACTION_ALERT;
  else if (strcmp (action_str, "drop") == 0)
    rule->action = IPS_ACTION_DROP;
  else if (strcmp (action_str, "reject") == 0)
    rule->action = IPS_ACTION_REJECT;
  else if (strcmp (action_str, "pass") == 0)
    rule->action = IPS_ACTION_PASS;
  else if (strcmp (action_str, "log") == 0)
    rule->action = IPS_ACTION_LOG;
  else
  {
    free (line_copy);
    return -1;
  }

  /* Parse protocol */
  protocol_str = ips_strtok_r (NULL, " \t", &saveptr);
  if (!protocol_str)
  {
    free (line_copy);
    return -1;
  }

  if (strcmp (protocol_str, "tcp") == 0)
    rule->protocol = IP_PROTOCOL_TCP;
  else if (strcmp (protocol_str, "udp") == 0)
    rule->protocol = IP_PROTOCOL_UDP;
  else if (strcmp (protocol_str, "icmp") == 0)
    rule->protocol = IP_PROTOCOL_ICMP;
  else if (strcmp (protocol_str, "ip") == 0)
    rule->protocol = 0; /* Any protocol */
  else
  {
    free (line_copy);
    return -1;
  }

  /* Parse src address */
  src_addr_str = ips_strtok_r (NULL, " \t", &saveptr);
  if (!src_addr_str)
  {
    free (line_copy);
    return -1;
  }

  /* For simplicity, set to any for now */
  rule->src_addr_mask = 0;

  /* Parse src port */
  src_port_str = ips_strtok_r (NULL, " \t", &saveptr);
  if (!src_port_str)
  {
    free (line_copy);
    return -1;
  }

  if (strcmp (src_port_str, "any") == 0)
  {
    rule->src_port_min = 0;
    rule->src_port_max = 65535;
  }
  else
  {
    rule->src_port_min = rule->src_port_max = atoi (src_port_str);
  }

  /* Parse direction */
  direction_str = ips_strtok_r (NULL, " \t", &saveptr);
  if (!direction_str)
  {
    free (line_copy);
    return -1;
  }

  if (strcmp (direction_str, "->") == 0)
    rule->direction = IPS_FLOW_DIR_TO_SERVER;
  else if (strcmp (direction_str, "<>") == 0)
    rule->direction = IPS_FLOW_DIR_BOTH;
  else
  {
    free (line_copy);
    return -1;
  }

  /* Parse dst address */
  dst_addr_str = ips_strtok_r (NULL, " \t", &saveptr);
  if (!dst_addr_str)
  {
    free (line_copy);
    return -1;
  }

  /* For simplicity, set to any for now */
  rule->dst_addr_mask = 0;

  /* Parse dst port */
  dst_port_str = ips_strtok_r (NULL, " \t", &saveptr);
  if (!dst_port_str)
  {
    free (line_copy);
    return -1;
  }

  if (strcmp (dst_port_str, "any") == 0)
  {
    rule->dst_port_min = 0;
    rule->dst_port_max = 65535;
  }
  else
  {
    rule->dst_port_min = rule->dst_port_max = atoi (dst_port_str);
  }

  /* Find options start */
  options_start = strchr (line, '(');
  if (options_start)
  {
    options_start++; /* Skip opening parenthesis */
    char *options_end = strrchr (line, ')');
    if (options_end)
    {
      *options_end = '\0'; /* Null terminate options */
      if (parse_multi_content_rule_options (options_start, rule) != 0)
      {
        free (line_copy);
        return -1;
      }
    }
  }

  free (line_copy);

  clib_warning ("Successfully parsed multi-content rule SID:%u with %u content patterns",
               rule->sid, rule->content_count);

  return 0;
}
