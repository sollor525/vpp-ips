/*
 * ips_pcre_hyperscan_enhanced.c - Enhanced VPP IPS Plugin PCRE to Hyperscan Conversion
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include "ips.h"
#include <vppinfra/clib.h>
#include <vppinfra/error.h>
#include <string.h>
#include <ctype.h>
#include <regex.h>

/* Enhanced PCRE to Hyperscan pattern conversion mapping */
typedef struct pcre_to_hs_map_t
{
  const char *pcre_pattern;    /* PCRE pattern */
  const char *hs_pattern;      /* Hyperscan equivalent */
  const char *description;     /* Description of conversion */
  int priority;                /* Conversion priority (higher = more important) */
} pcre_to_hs_map_t;

/* Enhanced PCRE to Hyperscan conversions with priority */
static const pcre_to_hs_map_t pcre_conversion_table[] = {
  /* High priority conversions - complex features */
  { "(?P<([^>]+)>", "(", "Python-style named groups", 100 },
  { "(?P=\\1)", "\\1", "Python-style backreferences", 100 },
  { "(?<([^>]+)>", "(", "Named capture groups", 90 },
  { "\\k<([^>]+)>", "\\1", "Named backreferences", 90 },

  /* Lookahead/lookbehind conversions */
  { "(?=([^)]+))", "\\1", "Positive lookahead (simplified)", 80 },
  { "(?!([^)]+))", "", "Negative lookahead (removed)", 80 },
  { "(?<=([^)]+))", "\\1", "Positive lookbehind (simplified)", 80 },
  { "(?<!([^)]+))", "", "Negative lookbehind (removed)", 80 },

  /* Atomic groups and possessive quantifiers */
  { "(?>)", ")", "Atomic groups", 70 },
  { "([+*?])\\+", "\\1", "Possessive quantifiers", 70 },

  /* Recursive patterns */
  { "(?R)", "", "Recursive patterns (removed)", 60 },
  { "(?[0-9]+)", "", "Recursive subpatterns (removed)", 60 },

  /* Conditional patterns */
  { "(?\\(", "(", "Conditional patterns", 50 },

  /* Character classes */
  { "\\d", "[0-9]", "Digit character class", 10 },
  { "\\D", "[^0-9]", "Non-digit character class", 10 },
  { "\\w", "[a-zA-Z0-9_]", "Word character class", 10 },
  { "\\W", "[^a-zA-Z0-9_]", "Non-word character class", 10 },
  { "\\s", "[ \\t\\r\\n\\f]", "Whitespace character class", 10 },
  { "\\S", "[^ \\t\\r\\n\\f]", "Non-whitespace character class", 10 },

  /* Word boundaries - Hyperscan supports these */
  { "\\b", "\\b", "Word boundary", 5 },
  { "\\B", "\\B", "Non-word boundary", 5 },

  /* Anchors */
  { "^", "^", "Beginning of line", 5 },
  { "$", "$", "End of line", 5 },

  /* Quantifiers */
  { "*", "*", "Zero or more", 5 },
  { "+", "+", "One or more", 5 },
  { "?", "?", "Zero or one", 5 },
  { "{n}", "{n}", "Exactly n times", 5 },
  { "{n,}", "{n,}", "n or more times", 5 },
  { "{n,m}", "{n,m}", "Between n and m times", 5 },

  /* Special characters */
  { ".", ".", "Any character", 5 },
  { "\\.", "\\.", "Literal dot", 5 },
  { "\\*", "\\*", "Literal asterisk", 5 },
  { "\\+", "\\+", "Literal plus", 5 },
  { "\\?", "\\?", "Literal question mark", 5 },
  { "\\(", "\\(", "Literal left parenthesis", 5 },
  { "\\)", "\\)", "Literal right parenthesis", 5 },
  { "\\[", "\\[", "Literal left bracket", 5 },
  { "\\]", "\\]", "Literal right bracket", 5 },
  { "\\{", "\\{", "Literal left brace", 5 },
  { "\\}", "\\}", "Literal right brace", 5 },
  { "\\|", "\\|", "Literal pipe", 5 },
  { "\\\\", "\\\\", "Literal backslash", 5 },

  /* Groups */
  { "(", "(", "Capturing group", 5 },
  { ")", ")", "End capturing group", 5 },
  { "(?:", "(?:", "Non-capturing group", 5 },
  { "|", "|", "Alternation", 5 },

  /* Character ranges */
  { "[a-z]", "[a-z]", "Lowercase letters", 5 },
  { "[A-Z]", "[A-Z]", "Uppercase letters", 5 },
  { "[0-9]", "[0-9]", "Digits", 5 },
  { "[^", "[^", "Negated character class", 5 },

  /* ASCII character classes - convert |28| to \x1c, |29| to \x1d, etc. */
  { "|28|", "\\x1c", "ASCII character 28 (FS)", 15 },
  { "|29|", "\\x1d", "ASCII character 29 (GS)", 15 },
  { "|30|", "\\x1e", "ASCII character 30 (RS)", 15 },
  { "|31|", "\\x1f", "ASCII character 31 (US)", 15 },
  { "|00|", "\\x00", "ASCII character 0 (NUL)", 15 },
  { "|01|", "\\x01", "ASCII character 1 (SOH)", 15 },
  { "|02|", "\\x02", "ASCII character 2 (STX)", 15 },
  { "|03|", "\\x03", "ASCII character 3 (ETX)", 15 },
  { "|04|", "\\x04", "ASCII character 4 (EOT)", 15 },
  { "|05|", "\\x05", "ASCII character 5 (ENQ)", 15 },
  { "|06|", "\\x06", "ASCII character 6 (ACK)", 15 },
  { "|07|", "\\x07", "ASCII character 7 (BEL)", 15 },
  { "|08|", "\\x08", "ASCII character 8 (BS)", 15 },
  { "|09|", "\\x09", "ASCII character 9 (HT)", 15 },
  { "|0A|", "\\x0a", "ASCII character 10 (LF)", 15 },
  { "|0B|", "\\x0b", "ASCII character 11 (VT)", 15 },
  { "|0C|", "\\x0c", "ASCII character 12 (FF)", 15 },
  { "|0D|", "\\x0d", "ASCII character 13 (CR)", 15 },
  { "|0E|", "\\x0e", "ASCII character 14 (SO)", 15 },
  { "|0F|", "\\x0f", "ASCII character 15 (SI)", 15 },
  { "|10|", "\\x10", "ASCII character 16 (DLE)", 15 },
  { "|11|", "\\x11", "ASCII character 17 (DC1)", 15 },
  { "|12|", "\\x12", "ASCII character 18 (DC2)", 15 },
  { "|13|", "\\x13", "ASCII character 19 (DC3)", 15 },
  { "|14|", "\\x14", "ASCII character 20 (DC4)", 15 },
  { "|15|", "\\x15", "ASCII character 21 (NAK)", 15 },
  { "|16|", "\\x16", "ASCII character 22 (SYN)", 15 },
  { "|17|", "\\x17", "ASCII character 23 (ETB)", 15 },
  { "|18|", "\\x18", "ASCII character 24 (CAN)", 15 },
  { "|19|", "\\x19", "ASCII character 25 (EM)", 15 },
  { "|1A|", "\\x1a", "ASCII character 26 (SUB)", 15 },
  { "|1B|", "\\x1b", "ASCII character 27 (ESC)", 15 },
  { "|1C|", "\\x1c", "ASCII character 28 (FS)", 15 },
  { "|1D|", "\\x1d", "ASCII character 29 (GS)", 15 },
  { "|1E|", "\\x1e", "ASCII character 30 (RS)", 15 },
  { "|1F|", "\\x1f", "ASCII character 31 (US)", 15 },
  { "|20|", "\\x20", "ASCII character 32 (SPACE)", 15 },
  { "|7F|", "\\x7f", "ASCII character 127 (DEL)", 15 },

  /* End of table */
  { NULL, NULL, NULL, 0 }
};

/* Unsupported PCRE features that cannot be converted */
static const char *unsupported_pcre_features[] = {
  "(?C",     /* Callout patterns */
  "(?X",     /* Script runs */
  "(?R",     /* Recursive patterns (complex) */
  "(?[0-9]+", /* Recursive subpatterns (complex) */
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
 * @brief Convert Python-style named groups to regular groups
 */
static int
convert_python_named_groups (char *pattern, u8 **error_msg)
{
  char *result = clib_mem_alloc (strlen (pattern) * 2 + 1);
  if (!result)
  {
    if (error_msg)
      *error_msg = format (0, "Memory allocation failed%c", 0);
    return -1;
  }

  char *src = pattern;
  char *dst = result;

  while (*src)
  {
    if (strncmp (src, "(?P<", 4) == 0)
    {
      /* Convert (?P<name>...) to (...) */
      *dst++ = '(';
      src += 4;

      /* Skip the group name */
      while (*src && *src != '>')
        src++;

      if (*src == '>')
        src++; /* Skip the closing > */
    }
    else if (strncmp (src, "(?P=", 4) == 0)
    {
      /* Convert (?P=name) to \1 (simplified) */
      *dst++ = '\\';
      *dst++ = '1';
      src += 4;

      /* Skip the group name */
      while (*src && *src != ')')
        src++;

      if (*src == ')')
        src++; /* Skip the closing ) */
    }
    else
    {
      *dst++ = *src++;
    }
  }

  *dst = '\0';

  /* Replace original pattern */
  strcpy (pattern, result);
  clib_mem_free (result);

  return 0;
}

/**
 * @brief Convert lookahead/lookbehind patterns
 */
static int
convert_lookaround_patterns (char *pattern, u8 **error_msg)
{
  char *result = clib_mem_alloc (strlen (pattern) * 2 + 1);
  if (!result)
  {
    if (error_msg)
      *error_msg = format (0, "Memory allocation failed%c", 0);
    return -1;
  }

  char *src = pattern;
  char *dst = result;

  while (*src)
  {
    if (strncmp (src, "(?=", 3) == 0)
    {
      /* Convert positive lookahead to simple pattern */
      src += 3;
      int paren_count = 1;

      while (*src && paren_count > 0)
      {
        if (*src == '(')
          paren_count++;
        else if (*src == ')')
          paren_count--;

        if (paren_count > 0)
          *dst++ = *src;
        src++;
      }
    }
    else if (strncmp (src, "(?!", 3) == 0)
    {
      /* Remove negative lookahead */
      src += 3;
      int paren_count = 1;

      while (*src && paren_count > 0)
      {
        if (*src == '(')
          paren_count++;
        else if (*src == ')')
          paren_count--;
        src++;
      }
    }
    else if (strncmp (src, "(?<=", 4) == 0)
    {
      /* Convert positive lookbehind to simple pattern */
      src += 4;
      int paren_count = 1;

      while (*src && paren_count > 0)
      {
        if (*src == '(')
          paren_count++;
        else if (*src == ')')
          paren_count--;

        if (paren_count > 0)
          *dst++ = *src;
        src++;
      }
    }
    else if (strncmp (src, "(?<!", 4) == 0)
    {
      /* Remove negative lookbehind */
      src += 4;
      int paren_count = 1;

      while (*src && paren_count > 0)
      {
        if (*src == '(')
          paren_count++;
        else if (*src == ')')
          paren_count--;
        src++;
      }
    }
    else
    {
      *dst++ = *src++;
    }
  }

  *dst = '\0';

  /* Replace original pattern */
  strcpy (pattern, result);
  clib_mem_free (result);

  return 0;
}

/**
 * @brief Enhanced PCRE to Hyperscan conversion
 */
int
ips_convert_pcre_to_hyperscan_enhanced (const char *pcre_pattern, char **hs_pattern,
                                       unsigned int *hs_flags, u8 **error_msg)
{
  if (!pcre_pattern || !hs_pattern)
    return -1;

  /* Check for unsupported features first */
  if (check_unsupported_features (pcre_pattern, error_msg) != 0)
    return -1;

  /* Start with a copy of the original pattern */
  char *converted = clib_mem_alloc (strlen (pcre_pattern) * 3 + 1);
  if (!converted)
  {
    if (error_msg)
      *error_msg = format (0, "Memory allocation failed%c", 0);
    return -1;
  }

  strcpy (converted, pcre_pattern);

  /* Apply complex conversions first */
  if (convert_python_named_groups (converted, error_msg) != 0)
  {
    clib_mem_free (converted);
    return -1;
  }

  if (convert_lookaround_patterns (converted, error_msg) != 0)
  {
    clib_mem_free (converted);
    return -1;
  }

  /* Apply simple conversions from the table (sorted by priority) */
  int i;
  for (i = 0; pcre_conversion_table[i].pcre_pattern != NULL; i++)
  {
    /* Skip if already converted or if it's a simple pass-through */
    if (strcmp (pcre_conversion_table[i].pcre_pattern,
                pcre_conversion_table[i].hs_pattern) == 0)
      continue;

    /* Perform string replacement for basic patterns */
    char *pos = strstr (converted, pcre_conversion_table[i].pcre_pattern);
    while (pos)
    {
      /* Calculate the length difference */
      int old_len = strlen (pcre_conversion_table[i].pcre_pattern);
      int new_len = strlen (pcre_conversion_table[i].hs_pattern);
      int len_diff = new_len - old_len;

      if (len_diff > 0)
      {
        /* Need to expand the string */
        char *new_converted = clib_mem_alloc (strlen (converted) + len_diff + 1);
        if (!new_converted)
        {
          clib_mem_free (converted);
          if (error_msg)
            *error_msg = format (0, "Memory allocation failed during conversion%c", 0);
          return -1;
        }

        /* Copy the part before the pattern */
        int before_len = pos - converted;
        strncpy (new_converted, converted, before_len);
        new_converted[before_len] = '\0';

        /* Copy the new pattern */
        strcat (new_converted, pcre_conversion_table[i].hs_pattern);

        /* Copy the part after the pattern */
        strcat (new_converted, pos + old_len);

        /* Replace the old string */
        clib_mem_free (converted);
        converted = new_converted;
      }
      else
      {
        /* Can do in-place replacement */
        memmove (pos + new_len, pos + old_len, strlen (pos + old_len) + 1);
        memcpy (pos, pcre_conversion_table[i].hs_pattern, new_len);
      }

      clib_warning ("PCRE conversion: %s -> %s (%s, priority: %d)",
                   pcre_conversion_table[i].pcre_pattern,
                   pcre_conversion_table[i].hs_pattern,
                   pcre_conversion_table[i].description,
                   pcre_conversion_table[i].priority);

      /* Look for more occurrences */
      pos = strstr (converted, pcre_conversion_table[i].pcre_pattern);
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

  clib_warning ("Enhanced PCRE to Hyperscan conversion: '%s' -> '%s' (flags: 0x%x)",
               pcre_pattern, converted, hs_flags ? *hs_flags : 0);

  return 0;
}

/**
 * @brief Validate PCRE pattern for Hyperscan compatibility (enhanced)
 */
int
ips_validate_pcre_for_hyperscan_enhanced (const char *pcre_pattern, u8 **error_msg)
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
 * @brief Get conversion statistics
 */
void
ips_get_pcre_conversion_stats (void)
{
  int total_conversions = 0;
  int i;

  for (i = 0; pcre_conversion_table[i].pcre_pattern != NULL; i++)
  {
    total_conversions++;
  }

  clib_warning ("PCRE conversion table contains %d conversion rules", total_conversions);

  /* Print high priority conversions */
  clib_warning ("High priority conversions (priority >= 80):");
  for (i = 0; pcre_conversion_table[i].pcre_pattern != NULL; i++)
  {
    if (pcre_conversion_table[i].priority >= 80)
    {
      clib_warning ("  %s -> %s (%s)",
                   pcre_conversion_table[i].pcre_pattern,
                   pcre_conversion_table[i].hs_pattern,
                   pcre_conversion_table[i].description);
    }
  }
}
