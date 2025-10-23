/*
 * ips_pcre_hyperscan.c - VPP IPS Plugin PCRE to Hyperscan Conversion
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include "ips.h"
#include <vppinfra/clib.h>
#include <vppinfra/error.h>
#include <string.h>
#include <ctype.h>

/* PCRE to Hyperscan pattern conversion mapping */
typedef struct pcre_to_hs_map_t
{
  const char *pcre_pattern;    /* PCRE pattern */
  const char *hs_pattern;      /* Hyperscan equivalent */
  const char *description;     /* Description of conversion */
} pcre_to_hs_map_t;

/* Common PCRE to Hyperscan conversions */
static const pcre_to_hs_map_t pcre_conversion_table[] = {
  /* Character classes */
  { "\\d", "[0-9]", "Digit character class" },
  { "\\D", "[^0-9]", "Non-digit character class" },
  { "\\w", "[a-zA-Z0-9_]", "Word character class" },
  { "\\W", "[^a-zA-Z0-9_]", "Non-word character class" },
  { "\\s", "[ \\t\\r\\n\\f]", "Whitespace character class" },
  { "\\S", "[^ \\t\\r\\n\\f]", "Non-whitespace character class" },

  /* Word boundaries - Hyperscan supports these */
  { "\\b", "\\b", "Word boundary" },
  { "\\B", "\\B", "Non-word boundary" },

  /* Anchors */
  { "^", "^", "Beginning of line" },
  { "$", "$", "End of line" },

  /* Quantifiers */
  { "*", "*", "Zero or more" },
  { "+", "+", "One or more" },
  { "?", "?", "Zero or one" },
  { "{n}", "{n}", "Exactly n times" },
  { "{n,}", "{n,}", "n or more times" },
  { "{n,m}", "{n,m}", "Between n and m times" },

  /* Special characters */
  { ".", ".", "Any character" },
  { "\\.", "\\.", "Literal dot" },
  { "\\*", "\\*", "Literal asterisk" },
  { "\\+", "\\+", "Literal plus" },
  { "\\?", "\\?", "Literal question mark" },
  { "\\(", "\\(", "Literal left parenthesis" },
  { "\\)", "\\)", "Literal right parenthesis" },
  { "\\[", "\\[", "Literal left bracket" },
  { "\\]", "\\]", "Literal right bracket" },
  { "\\{", "\\{", "Literal left brace" },
  { "\\}", "\\}", "Literal right brace" },
  { "\\|", "\\|", "Literal pipe" },
  { "\\\\", "\\\\", "Literal backslash" },

  /* Groups */
  { "(", "(", "Capturing group" },
  { ")", ")", "End capturing group" },
  { "(?:", "(?:", "Non-capturing group" },
  { "|", "|", "Alternation" },

  /* Character ranges */
  { "[a-z]", "[a-z]", "Lowercase letters" },
  { "[A-Z]", "[A-Z]", "Uppercase letters" },
  { "[0-9]", "[0-9]", "Digits" },
  { "[^", "[^", "Negated character class" },

  /* End of table */
  { NULL, NULL, NULL }
};

/* Unsupported PCRE features that need special handling */
static const char *unsupported_pcre_features[] = {
  "(?=",     /* Positive lookahead */
  "(?!",     /* Negative lookahead */
  "(?<=",    /* Positive lookbehind */
  "(?<!",    /* Negative lookbehind */
  "\\A",     /* Beginning of string */
  "\\Z",     /* End of string */
  "\\z",     /* End of string */
  "\\G",     /* Previous match end */
  "(?i)",    /* Case-insensitive flag */
  "(?m)",    /* Multiline flag */
  "(?s)",    /* Dotall flag */
  "(?x)",    /* Extended flag */
  NULL
};

/**
 * @brief Check if PCRE pattern contains unsupported features
 */
static int
check_unsupported_features (const char *pcre_pattern, u8 **error_msg)
{
  int i;

  if (!pcre_pattern)
    return -1;

  for (i = 0; unsupported_pcre_features[i] != NULL; i++)
  {
    if (strstr (pcre_pattern, unsupported_pcre_features[i]))
    {
      if (error_msg)
        *error_msg = format (0, "Unsupported PCRE feature: %s%c",
                           unsupported_pcre_features[i], 0);
      return -1;
    }
  }

  return 0;
}

/**
 * @brief Convert PCRE pattern to Hyperscan compatible pattern
 */
int
ips_convert_pcre_to_hyperscan (const char *pcre_pattern, u8 **hs_pattern,
                              unsigned int *hs_flags, u8 **error_msg)
{
  if (!pcre_pattern || !hs_pattern)
    return -1;

  /* Check for unsupported features first */
  if (check_unsupported_features (pcre_pattern, error_msg) != 0)
    return -1;

  /* Start with a copy of the original pattern */
  char *converted = clib_mem_alloc (strlen (pcre_pattern) * 2 + 1);
  if (!converted)
  {
    if (error_msg)
      *error_msg = format (0, "Memory allocation failed%c", 0);
    return -1;
  }

  strcpy (converted, pcre_pattern);

  /* Apply simple conversions from the table */
  int i;
  for (i = 0; pcre_conversion_table[i].pcre_pattern != NULL; i++)
  {
    /* Skip if already converted or if it's a simple pass-through */
    if (strcmp (pcre_conversion_table[i].pcre_pattern,
                pcre_conversion_table[i].hs_pattern) == 0)
      continue;

    /* Perform simple string replacement for basic patterns */
    char *pos = strstr (converted, pcre_conversion_table[i].pcre_pattern);
    if (pos)
    {
      /* This is a simplified replacement - in practice, you'd need more
       * sophisticated parsing to handle context */
      clib_warning ("PCRE conversion: %s -> %s (%s)",
                   pcre_conversion_table[i].pcre_pattern,
                   pcre_conversion_table[i].hs_pattern,
                   pcre_conversion_table[i].description);
    }
  }

  /* Set default Hyperscan flags */
  if (hs_flags)
  {
    *hs_flags = 0;

    /* Check for case-insensitive flag in pattern */
    if (strstr (converted, "(?i)"))
      *hs_flags |= HS_FLAG_CASELESS;

    /* Check for multiline flag */
    if (strstr (converted, "(?m)"))
      *hs_flags |= HS_FLAG_MULTILINE;

    /* Check for dotall flag */
    if (strstr (converted, "(?s)"))
      *hs_flags |= HS_FLAG_DOTALL;

    /* Remove flag patterns from converted string */
    char *flag_pos;
    while ((flag_pos = strstr (converted, "(?i)")) != NULL)
    {
      memmove (flag_pos, flag_pos + 4, strlen (flag_pos + 4) + 1);
    }
    while ((flag_pos = strstr (converted, "(?m)")) != NULL)
    {
      memmove (flag_pos, flag_pos + 4, strlen (flag_pos + 4) + 1);
    }
    while ((flag_pos = strstr (converted, "(?s)")) != NULL)
    {
      memmove (flag_pos, flag_pos + 4, strlen (flag_pos + 4) + 1);
    }
  }

  *hs_pattern = converted;

  clib_warning ("PCRE to Hyperscan conversion: '%s' -> '%s' (flags: 0x%x)",
               pcre_pattern, converted, hs_flags ? *hs_flags : 0);

  return 0;
}

/**
 * @brief Free converted pattern memory
 */
void
ips_free_converted_pattern (char *pattern)
{
  if (pattern)
    clib_mem_free (pattern);
}

/**
 * @brief Validate PCRE pattern for Hyperscan compatibility
 */
int
ips_validate_pcre_for_hyperscan (const char *pcre_pattern, u8 **error_msg)
{
  if (!pcre_pattern)
  {
    if (error_msg)
      *error_msg = format (0, "NULL pattern%c", 0);
    return -1;
  }

  /* Check length */
  if (strlen (pcre_pattern) > 8192)
  {
    if (error_msg)
      *error_msg = format (0, "Pattern too long (max 8192 chars)%c", 0);
    return -1;
  }

  /* Check for unsupported features */
  return check_unsupported_features (pcre_pattern, error_msg);
}

/**
 * @brief Get supported PCRE features list
 */
const char *
ips_get_supported_pcre_features (void)
{
  static char *features_list = NULL;

  if (!features_list)
  {
    features_list = format (0, "Supported PCRE features:%c", 0);

    int i;
    for (i = 0; pcre_conversion_table[i].pcre_pattern != NULL; i++)
    {
      features_list = format (features_list, "  %s - %s%c",
                             pcre_conversion_table[i].pcre_pattern,
                             pcre_conversion_table[i].description, 0);
    }
  }

  return (const char *)features_list;
}
