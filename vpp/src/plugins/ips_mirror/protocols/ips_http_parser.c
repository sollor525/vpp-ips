/*
 * ips_http_parser.c - VPP IPS HTTP Protocol Parser Implementation
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <vlib/vlib.h>
#include <vppinfra/string.h>
#include <ctype.h>

#include "ips_http_parser.h"
#include "../ips_logging.h"

/* HTTP method strings */
const char *ips_http_method_strings[] = {
    [IPS_HTTP_METHOD_UNKNOWN] = "UNKNOWN",
    [IPS_HTTP_METHOD_GET] = "GET",
    [IPS_HTTP_METHOD_POST] = "POST",
    [IPS_HTTP_METHOD_PUT] = "PUT",
    [IPS_HTTP_METHOD_DELETE] = "DELETE",
    [IPS_HTTP_METHOD_HEAD] = "HEAD",
    [IPS_HTTP_METHOD_OPTIONS] = "OPTIONS",
    [IPS_HTTP_METHOD_PATCH] = "PATCH",
    [IPS_HTTP_METHOD_CONNECT] = "CONNECT",
    [IPS_HTTP_METHOD_TRACE] = "TRACE",
};

/* HTTP method patterns for quick detection */
static const struct {
    const char *method;
    u8 len;
    ips_http_method_t type;
} http_methods[] = {
    {"GET ", 4, IPS_HTTP_METHOD_GET},
    {"POST", 4, IPS_HTTP_METHOD_POST},
    {"PUT ", 4, IPS_HTTP_METHOD_PUT},
    {"HEAD", 4, IPS_HTTP_METHOD_HEAD},
    {"DELE", 4, IPS_HTTP_METHOD_DELETE},  /* DELETE */
    {"OPTI", 4, IPS_HTTP_METHOD_OPTIONS}, /* OPTIONS */
    {"PATC", 4, IPS_HTTP_METHOD_PATCH},   /* PATCH */
    {"CONN", 4, IPS_HTTP_METHOD_CONNECT}, /* CONNECT */
    {"TRAC", 4, IPS_HTTP_METHOD_TRACE},   /* TRACE */
};

/**
 * @brief Initialize HTTP parser state
 */
void *
ips_http_parser_init(void)
{
    ips_http_parser_state_t *state = clib_mem_alloc(sizeof(ips_http_parser_state_t));
    if (!state)
        return NULL;

    clib_memset(state, 0, sizeof(*state));
    state->state = IPS_HTTP_STATE_NONE;

    return state;
}

/**
 * @brief Free HTTP parser state
 */
void
ips_http_parser_free(void *state)
{
    if (state)
        clib_mem_free(state);
}

/**
 * @brief Convert HTTP method to string
 */
const char *
ips_http_method_to_string(ips_http_method_t method)
{
    if (method < IPS_HTTP_METHOD_MAX)
        return ips_http_method_strings[method];
    return "UNKNOWN";
}

/**
 * @brief Parse HTTP method from data
 */
ips_http_method_t
ips_http_parse_method(const u8 *data, u32 len)
{
    if (!data || len < 4)
        return IPS_HTTP_METHOD_UNKNOWN;

    for (u32 i = 0; i < ARRAY_LEN(http_methods); i++)
    {
        if (len >= http_methods[i].len &&
            clib_memcmp(data, http_methods[i].method, http_methods[i].len) == 0)
        {
            return http_methods[i].type;
        }
    }

    return IPS_HTTP_METHOD_UNKNOWN;
}

/**
 * @brief Check if HTTP status code is valid
 */
int
ips_http_is_valid_status_code(u16 code)
{
    return (code >= 100 && code < 600);
}

/**
 * @brief Check if header name is valid
 */
int
ips_http_is_valid_header_name(const u8 *data, u32 len)
{
    if (!data || len == 0)
        return 0;

    for (u32 i = 0; i < len; i++)
    {
        u8 c = data[i];
        /* Header names can contain: !#$%&'*+.^_`|~ and digits and letters */
        if (!((c >= 'A' && c <= 'Z') ||
              (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') ||
              c == '-' || c == '_' || c == '.' ||
              c == '~' || c == '!' || c == '#' ||
              c == '$' || c == '%' || c == '&' ||
              c == '\'' || c == '*' || c == '+' ||
              c == '^' || c == '`' || c == '|'))
        {
            return 0;
        }
    }

    return 1;
}

/**
 * @brief HTTP protocol probe function
 */
u8
ips_http_probe(u8 *data, u32 len, u8 direction)
{
    if (!data || len < 4)
        return 0;

    /* Client->Server: Check for HTTP methods */
    if (direction == 0)
    {
        ips_http_method_t method = ips_http_parse_method(data, len);
        if (method != IPS_HTTP_METHOD_UNKNOWN)
        {
            /* Additional validation: check for HTTP version */
            for (u32 i = 0; i < len - 8; i++)
            {
                if (clib_memcmp(&data[i], "HTTP/1.", 7) == 0)
                {
                    u8 version = data[i + 7];
                    if (version == '0' || version == '1')
                        return 95;  /* High confidence */
                }
            }
            return 85;  /* Good confidence */
        }
    }
    /* Server->Client: Check for HTTP response */
    else
    {
        if (len >= 9 && clib_memcmp(data, "HTTP/1.", 7) == 0)
        {
            u8 version = data[7];
            if ((version == '0' || version == '1') && data[8] == ' ')
            {
                /* Check for valid status code */
                if (len >= 12 &&
                    isdigit(data[9]) && isdigit(data[10]) && isdigit(data[11]))
                {
                    u16 status = (data[9] - '0') * 100 +
                                (data[10] - '0') * 10 +
                                (data[11] - '0');

                    if (ips_http_is_valid_status_code(status))
                        return 95;  /* High confidence */
                }
                return 85;  /* Good confidence */
            }
        }
    }

    return 0;
}

/**
 * @brief Parse HTTP request line
 */
static int
ips_http_parse_request_line(ips_http_parser_state_t *state,
                            const u8 *data, u32 len)
{
    if (!state || !data || len < 8)
        return -1;

    /* Parse method */
    state->method = ips_http_parse_method(data, len);
    if (state->method == IPS_HTTP_METHOD_UNKNOWN)
        return -1;

    /* Find URL (after method and space) */
    u32 offset = 0;
    while (offset < len && data[offset] != ' ')
        offset++;
    if (offset >= len)
        return -1;
    offset++;  /* Skip space */

    /* URL starts here */
    state->url_offset = offset;

    /* Find end of URL (space before HTTP version) */
    while (offset < len && data[offset] != ' ')
        offset++;
    if (offset >= len)
        return -1;

    state->url_len = offset - state->url_offset;

    /* Parse HTTP version */
    if (offset + 8 <= len && clib_memcmp(&data[offset], " HTTP/1.", 8) == 0)
    {
        offset += 8;
        if (offset < len)
        {
            if (data[offset] == '0')
            {
                state->version_major = 1;
                state->version_minor = 0;
            }
            else if (data[offset] == '1')
            {
                state->version_major = 1;
                state->version_minor = 1;
            }
        }
    }

    state->request_count++;
    return 0;
}

/**
 * @brief Parse HTTP response line
 */
static int
ips_http_parse_response_line(ips_http_parser_state_t *state,
                             const u8 *data, u32 len)
{
    if (!state || !data || len < 12)
        return -1;

    /* Parse HTTP version */
    if (len >= 8 && clib_memcmp(data, "HTTP/1.", 7) == 0)
    {
        if (data[7] == '0')
        {
            state->version_major = 1;
            state->version_minor = 0;
        }
        else if (data[7] == '1')
        {
            state->version_major = 1;
            state->version_minor = 1;
        }
    }

    /* Parse status code */
    if (len >= 12 && data[8] == ' ' &&
        isdigit(data[9]) && isdigit(data[10]) && isdigit(data[11]))
    {
        state->status_code = (data[9] - '0') * 100 +
                            (data[10] - '0') * 10 +
                            (data[11] - '0');

        if (!ips_http_is_valid_status_code(state->status_code))
            return -1;
    }

    state->response_count++;
    return 0;
}

/**
 * @brief Main HTTP parsing function
 */
int
ips_http_parse(void *parser_state, u8 *data, u32 len, u8 direction,
               ips_proto_state_t *proto_state, ips_proto_flags_t *flags)
{
    ips_http_parser_state_t *state = (ips_http_parser_state_t *)parser_state;

    if (!state || !data || len == 0 || !proto_state || !flags)
        return -1;

    state->total_bytes += len;

    /* Reset state if we're starting a new message */
    if (state->state == IPS_HTTP_STATE_COMPLETE || state->state == IPS_HTTP_STATE_NONE)
    {
        if (direction == 0)
            state->state = IPS_HTTP_STATE_REQUEST_LINE;
        else
            state->state = IPS_HTTP_STATE_RESPONSE_LINE;
    }

    /* Parse based on current state */
    switch (state->state)
    {
    case IPS_HTTP_STATE_REQUEST_LINE:
        if (ips_http_parse_request_line(state, data, len) == 0)
        {
            state->state = IPS_HTTP_STATE_HEADERS;
            *proto_state = IPS_PROTO_STATE_ESTABLISHED;
            state->flags |= IPS_HTTP_FLAG_HAS_HEADERS;
        }
        else
        {
            state->flags |= IPS_HTTP_FLAG_ANOMALY;
        }
        break;

    case IPS_HTTP_STATE_RESPONSE_LINE:
        if (ips_http_parse_response_line(state, data, len) == 0)
        {
            state->state = IPS_HTTP_STATE_HEADERS;
            *proto_state = IPS_PROTO_STATE_ESTABLISHED;
            state->flags |= IPS_HTTP_FLAG_HAS_HEADERS;
        }
        else
        {
            state->flags |= IPS_HTTP_FLAG_ANOMALY;
        }
        break;

    case IPS_HTTP_STATE_HEADERS:
        /* Simple header detection - look for end of headers (\r\n\r\n) */
        for (u32 i = 0; i < len - 3; i++)
        {
            if (data[i] == '\r' && data[i+1] == '\n' &&
                data[i+2] == '\r' && data[i+3] == '\n')
            {
                state->headers_complete = 1;
                state->state = IPS_HTTP_STATE_BODY;
                state->flags |= IPS_HTTP_FLAG_HAS_HEADERS;

                /* Look for Content-Length header */
                for (u32 j = 0; j < i - 16; j++)
                {
                    if (clib_memcmp(&data[j], "Content-Length:", 15) == 0)
                    {
                        /* Parse content length value */
                        u32 k = j + 15;
                        while (k < i && isspace(data[k]))
                            k++;

                        u32 content_len = 0;
                        while (k < i && isdigit(data[k]))
                        {
                            content_len = content_len * 10 + (data[k] - '0');
                            k++;
                        }

                        state->content_length = content_len;
                        break;
                    }
                }
                break;
            }
        }

        /* Look for important headers */
        if (!state->host_len && len > 6)
        {
            for (u32 i = 0; i < len - 6; i++)
            {
                if (clib_memcmp(&data[i], "Host:", 5) == 0)
                {
                    u32 start = i + 5;
                    while (start < len && isspace(data[start]))
                        start++;

                    u32 end = start;
                    while (end < len && data[end] != '\r' && data[end] != '\n')
                        end++;

                    if (end > start)
                    {
                        state->host_offset = start;
                        state->host_len = end - start;
                    }
                    break;
                }
            }
        }

        /* Check for TLS upgrade (HTTPS CONNECT) */
        if (state->method == IPS_HTTP_METHOD_CONNECT)
        {
            state->flags |= IPS_HTTP_FLAG_TLS;
            *flags |= IPS_PROTO_FLAG_ENCRYPTED;
        }
        break;

    case IPS_HTTP_STATE_BODY:
        state->body_bytes_read += len;

        if (state->content_length > 0)
        {
            if (state->body_bytes_read >= state->content_length)
            {
                state->state = IPS_HTTP_STATE_COMPLETE;
                *proto_state = IPS_PROTO_STATE_ESTABLISHED;
            }
        }
        else
        {
            /* No content-length, assume complete for this packet */
            state->state = IPS_HTTP_STATE_COMPLETE;
        }
        state->flags |= IPS_HTTP_FLAG_HAS_BODY;
        break;

    case IPS_HTTP_STATE_COMPLETE:
        /* Ready for next HTTP message */
        state->state = IPS_HTTP_STATE_NONE;
        break;

    default:
        break;
    }

    return 0;
}

/**
 * @brief Check for HTTP protocol anomalies
 */
int
ips_http_check_anomaly(void *parser_state, u8 *data, u32 len, u8 direction)
{
    ips_http_parser_state_t *state = (ips_http_parser_state_t *)parser_state;

    if (!state || !data || len == 0)
        return 0;

    /* Check for common HTTP anomalies */

    /* 1. Invalid HTTP method */
    if (direction == 0 && state->state == IPS_HTTP_STATE_REQUEST_LINE)
    {
        if (state->method == IPS_HTTP_METHOD_UNKNOWN)
            return 1;
    }

    /* 2. Invalid HTTP status code */
    if (direction == 1 && state->state == IPS_HTTP_STATE_RESPONSE_LINE)
    {
        if (!ips_http_is_valid_status_code(state->status_code))
            return 1;
    }

    /* 3. Suspiciously long headers */
    if (len > 8192)  /* 8KB header limit */
        return 1;

    /* 4. Binary data in HTTP headers */
    for (u32 i = 0; i < clib_min(len, 256); i++)
    {
        if (data[i] < 0x20 && data[i] != '\r' && data[i] != '\n' && data[i] != '\t')
            return 1;
    }

    return 0;
}

/**
 * @brief Get HTTP metadata for logging
 */
int
ips_http_get_metadata(void *parser_state, char *buffer, u32 buffer_len)
{
    ips_http_parser_state_t *state = (ips_http_parser_state_t *)parser_state;

    if (!state || !buffer || buffer_len < 64)
        return -1;

    int written = 0;

    /* Basic HTTP info */
    if (state->request_count > 0)
    {
        written += snprintf(buffer + written, buffer_len - written,
                           "HTTP/1.%d %s reqs:%u resp:%u",
                           state->version_minor,
                           ips_http_method_to_string(state->method),
                           state->request_count,
                           state->response_count);
    }
    else if (state->response_count > 0)
    {
        written += snprintf(buffer + written, buffer_len - written,
                           "HTTP/1.%d status:%u reqs:%u resp:%u",
                           state->version_minor,
                           state->status_code,
                           state->request_count,
                           state->response_count);
    }

    /* Add flags */
    if (state->flags & IPS_HTTP_FLAG_TLS)
        written += snprintf(buffer + written, buffer_len - written, " TLS");
    if (state->flags & IPS_HTTP_FLAG_ANOMALY)
        written += snprintf(buffer + written, buffer_len - written, " ANOMALY");

    return written;
}