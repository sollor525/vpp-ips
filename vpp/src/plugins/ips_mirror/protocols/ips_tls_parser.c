/*
 * ips_tls_parser.c - VPP IPS TLS/SSL Protocol Parser Implementation
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <vlib/vlib.h>
#include <vppinfra/string.h>
#include <ctype.h>

#include "ips_tls_parser.h"
#include "../ips_logging.h"

/* TLS version strings */
const char *ips_tls_version_strings[] = {
    "SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"
};

/* Common TLS cipher suites for identification */
static const struct {
    u16 id;
    const char *name;
} tls_cipher_suites[] = {
    {0x0005, "TLS_RSA_WITH_RC4_128_SHA"},
    {0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA"},
    {0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"},
    {0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256"},
    {0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384"},
    {0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"},
    {0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"},
    {0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
    {0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
    {0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
    {0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
};

/**
 * @brief Initialize TLS parser state
 */
void *
ips_tls_parser_init(void)
{
    ips_tls_parser_state_t *state = clib_mem_alloc(sizeof(ips_tls_parser_state_t));
    if (!state)
        return NULL;

    clib_memset(state, 0, sizeof(*state));
    state->state = IPS_TLS_STATE_NONE;
    state->version.major = 0xFF;  /* Unknown */
    state->version.minor = 0xFF;

    return state;
}

/**
 * @brief Free TLS parser state
 */
void
ips_tls_parser_free(void *state)
{
    if (state)
        clib_mem_free(state);
}

/**
 * @brief Convert TLS version to string
 */
const char *
ips_tls_version_to_string(ips_tls_version_t version)
{
    if (version.major == 0x03)
    {
        switch (version.minor)
        {
        case 0: return "SSLv3";
        case 1: return "TLSv1.0";
        case 2: return "TLSv1.1";
        case 3: return "TLSv1.2";
        case 4: return "TLSv1.3";
        }
    }
    else if (version.major == 0x02)
    {
        return "SSLv2";
    }

    return "Unknown";
}

/**
 * @brief Convert TLS content type to string
 */
const char *
ips_tls_content_type_to_string(u8 content_type)
{
    switch (content_type)
    {
    case IPS_TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC: return "ChangeCipherSpec";
    case IPS_TLS_CONTENT_TYPE_ALERT: return "Alert";
    case IPS_TLS_CONTENT_TYPE_HANDSHAKE: return "Handshake";
    case IPS_TLS_CONTENT_TYPE_APPLICATION_DATA: return "ApplicationData";
    case IPS_TLS_CONTENT_TYPE_HEARTBEAT: return "Heartbeat";
    default: return "Unknown";
    }
}

/**
 * @brief Convert TLS handshake type to string
 */
const char *
ips_tls_handshake_type_to_string(u8 handshake_type)
{
    switch (handshake_type)
    {
    case IPS_TLS_HANDSHAKE_HELLO_REQUEST: return "HelloRequest";
    case IPS_TLS_HANDSHAKE_CLIENT_HELLO: return "ClientHello";
    case IPS_TLS_HANDSHAKE_SERVER_HELLO: return "ServerHello";
    case IPS_TLS_HANDSHAKE_CERTIFICATE: return "Certificate";
    case IPS_TLS_HANDSHAKE_SERVER_KEY_EXCHANGE: return "ServerKeyExchange";
    case IPS_TLS_HANDSHAKE_CERTIFICATE_REQUEST: return "CertificateRequest";
    case IPS_TLS_HANDSHAKE_SERVER_HELLO_DONE: return "ServerHelloDone";
    case IPS_TLS_HANDSHAKE_CERTIFICATE_VERIFY: return "CertificateVerify";
    case IPS_TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE: return "ClientKeyExchange";
    case IPS_TLS_HANDSHAKE_FINISHED: return "Finished";
    default: return "Unknown";
    }
}

/**
 * @brief Check if TLS version is valid
 */
int
ips_tls_is_valid_version(u8 major, u8 minor)
{
    if (major == 0x03 && minor <= 4)  /* SSLv3, TLSv1.0-1.3 */
        return 1;
    if (major == 0x02)  /* SSLv2 */
        return 1;
    return 0;
}

/**
 * @brief Check if cipher suite is known
 */
int
ips_tls_is_valid_cipher_suite(u16 cipher_suite)
{
    for (u32 i = 0; i < ARRAY_LEN(tls_cipher_suites); i++)
    {
        if (tls_cipher_suites[i].id == cipher_suite)
            return 1;
    }
    return 0;
}

/**
 * @brief Extract SNI from TLS ClientHello
 */
int
ips_tls_extract_sni(const u8 *data, u32 len, u8 *sni, u8 *sni_len)
{
    if (!data || len < 40 || !sni || !sni_len)
        return -1;

    /* Skip TLS record header (5 bytes) and handshake header (4 bytes) */
    u32 offset = 9;

    /* Skip protocol version (2) and random (32) */
    offset += 34;

    /* Skip session ID */
    if (offset >= len)
        return -1;
    u8 session_id_len = data[offset++];
    offset += session_id_len;
    if (offset >= len)
        return -1;

    /* Skip cipher suites */
    if (offset + 1 >= len)
        return -1;
    u16 cipher_suites_len = (data[offset] << 8) | data[offset + 1];
    offset += 2 + cipher_suites_len;
    if (offset >= len)
        return -1;

    /* Skip compression methods */
    if (offset >= len)
        return -1;
    u8 compression_methods_len = data[offset++];
    offset += compression_methods_len;
    if (offset >= len)
        return -1;

    /* Check if extensions are present */
    if (offset + 1 >= len)
        return -1;
    u16 extensions_len = (data[offset] << 8) | data[offset + 1];
    offset += 2;

    if (offset + extensions_len > len)
        return -1;

    /* Parse extensions looking for SNI (0x0000) */
    u32 end_offset = offset + extensions_len;
    while (offset + 4 <= end_offset)
    {
        u16 ext_type = (data[offset] << 8) | data[offset + 1];
        u16 ext_len = (data[offset + 2] << 8) | data[offset + 3];
        offset += 4;

        if (offset + ext_len > end_offset)
            break;

        if (ext_type == 0x0000)  /* SNI extension */
        {
            /* Skip SNI list length (2) */
            if (ext_len < 3)
                break;
            offset += 2;

            /* Skip SNI type (1) - should be 0 for hostname */
            u8 sni_type = data[offset++];
            if (sni_type != 0)
                break;

            /* Get SNI length */
            u16 name_len = (data[offset] << 8) | data[offset + 1];
            offset += 2;

            if (offset + name_len > end_offset)
                break;

            u16 copy_len = clib_min(name_len, (u16)255);
            clib_memcpy(sni, &data[offset], copy_len);
            sni[copy_len] = '\0';
            *sni_len = copy_len;

            return 0;
        }

        offset += ext_len;
    }

    return -1;
}

/**
 * @brief TLS protocol probe function
 */
u8
ips_tls_probe(u8 *data, u32 len, u8 __clib_unused direction)
{
    if (!data || len < 5)
        return 0;

    /* TLS record format:
     * Byte 0: Content Type
     * Byte 1-2: Version (major, minor)
     * Byte 3-4: Length
     */

    u8 content_type = data[0];
    u8 major = data[1];
    u8 minor = data[2];

    /* Check content type */
    if (content_type < 20 || content_type > 24)
        return 0;

    /* Check version */
    if (!ips_tls_is_valid_version(major, minor))
        return 0;

    /* Check length */
    u16 record_len = (data[3] << 8) | data[4];
    if (record_len < 1 || record_len > 16384)  /* TLS max record size */
        return 0;

    /* Additional validation: check if total length makes sense */
    if (len < 5 + record_len)
        return 0;

    /* Higher confidence for handshake records */
    if (content_type == IPS_TLS_CONTENT_TYPE_HANDSHAKE)
        return 95;

    /* Good confidence for other TLS record types */
    return 85;
}

/**
 * @brief Parse TLS ClientHello message
 */
static int
ips_tls_parse_client_hello(ips_tls_parser_state_t *state,
                           const u8 *data, u32 len)
{
    if (!state || !data || len < 38)
        return -1;

    /* Parse version from ClientHello */
    u8 major = data[0];
    u8 minor = data[1];
    if (ips_tls_is_valid_version(major, minor))
    {
        state->version.major = major;
        state->version.minor = minor;
    }

    /* Extract client random */
    if (len >= 34)
    {
        clib_memcpy(state->client_random, &data[2], 32);
    }

    /* Try to extract SNI */
    if (len > 50)  /* Minimum length for extensions */
    {
        ips_tls_extract_sni(data, len, state->sni, &state->sni_length);
    }

    state->flags |= IPS_TLS_FLAG_CLIENT_HELLO_SEEN;
    state->handshake_messages_seen |= (1ULL << IPS_TLS_HANDSHAKE_CLIENT_HELLO);

    return 0;
}

/**
 * @brief Parse TLS ServerHello message
 */
static int
ips_tls_parse_server_hello(ips_tls_parser_state_t *state,
                           const u8 *data, u32 len)
{
    if (!state || !data || len < 38)
        return -1;

    /* Parse version */
    u8 major = data[0];
    u8 minor = data[1];
    if (ips_tls_is_valid_version(major, minor))
    {
        state->version.major = major;
        state->version.minor = minor;
    }

    /* Extract server random */
    if (len >= 34)
    {
        clib_memcpy(state->server_random, &data[2], 32);
    }

    /* Extract session ID */
    u32 offset = 34;
    if (offset < len)
    {
        u8 session_id_len = data[offset++];
        if (session_id_len > 0 && session_id_len <= 32 && offset + session_id_len <= len)
        {
            clib_memcpy(state->session_id, &data[offset], session_id_len);
            state->session_id_length = session_id_len;
            offset += session_id_len;
        }
    }

    /* Extract selected cipher suite */
    if (offset + 2 <= len)
    {
        state->selected_cipher_suite = (data[offset] << 8) | data[offset + 1];
        offset += 2;
    }

    /* Extract compression method */
    if (offset < len)
    {
        state->compression_method = data[offset];
    }

    state->flags |= IPS_TLS_FLAG_SERVER_HELLO_SEEN;
    state->handshake_messages_seen |= (1ULL << IPS_TLS_HANDSHAKE_SERVER_HELLO);

    return 0;
}

/**
 * @brief Main TLS parsing function
 */
int
ips_tls_parse(void *parser_state, u8 *data, u32 len, u8 direction,
               ips_proto_state_t *proto_state, ips_proto_flags_t *flags)
{
    ips_tls_parser_state_t *state = (ips_tls_parser_state_t *)parser_state;

    if (!state || !data || len < 5 || !proto_state || !flags)
        return -1;

    state->total_bytes += len;
    state->records_processed++;

    /* Parse TLS record header */
    u8 content_type = data[0];
    u8 major = data[1];
    u8 minor = data[2];
    u16 record_len = (data[3] << 8) | data[4];

    /* Validate record header */
    if (!ips_tls_is_valid_version(major, minor) ||
        record_len < 1 || record_len > 16384 ||
        len < 5 + record_len)
    {
        state->flags |= IPS_TLS_FLAG_ANOMALY;
        return -1;
    }

    /* Update version information */
    if (state->version.major == 0xFF)  /* First record */
    {
        state->version.major = major;
        state->version.minor = minor;
    }

    u8 *payload = &data[5];
    u32 payload_len = record_len;

    /* Handle different content types */
    switch (content_type)
    {
    case IPS_TLS_CONTENT_TYPE_HANDSHAKE:
        state->handshake_bytes += payload_len;

        if (payload_len > 0)
        {
            u8 handshake_type = payload[0];

            switch (handshake_type)
            {
            case IPS_TLS_HANDSHAKE_CLIENT_HELLO:
                if (direction == 0)  /* Client -> Server */
                {
                    ips_tls_parse_client_hello(state, payload, payload_len);
                    state->state = IPS_TLS_STATE_HANDSHAKE;
                }
                break;

            case IPS_TLS_HANDSHAKE_SERVER_HELLO:
                if (direction == 1)  /* Server -> Client */
                {
                    ips_tls_parse_server_hello(state, payload, payload_len);
                }
                break;

            case IPS_TLS_HANDSHAKE_CERTIFICATE:
                state->flags |= IPS_TLS_FLAG_CERTIFICATE_SEEN;
                state->certificate_count++;
                state->handshake_messages_seen |= (1ULL << IPS_TLS_HANDSHAKE_CERTIFICATE);
                break;

            case IPS_TLS_HANDSHAKE_FINISHED:
                /* Handshake complete */
                state->state = IPS_TLS_STATE_ESTABLISHED;
                *proto_state = IPS_PROTO_STATE_ESTABLISHED;
                *flags |= IPS_PROTO_FLAG_ENCRYPTED;
                state->flags |= IPS_TLS_FLAG_ENCRYPTED;
                break;
            }
        }
        break;

    case IPS_TLS_CONTENT_TYPE_APPLICATION_DATA:
        state->application_data_records++;
        if (state->state != IPS_TLS_STATE_ESTABLISHED)
        {
            /* First application data - connection is established */
            state->state = IPS_TLS_STATE_ESTABLISHED;
            *proto_state = IPS_PROTO_STATE_ESTABLISHED;
            *flags |= IPS_PROTO_FLAG_ENCRYPTED;
            state->flags |= IPS_TLS_FLAG_ENCRYPTED;
        }
        break;

    case IPS_TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC:
        state->encrypted_records++;
        break;

    case IPS_TLS_CONTENT_TYPE_ALERT:
        /* Could be connection close alert */
        break;

    default:
        state->flags |= IPS_TLS_FLAG_ANOMALY;
        break;
    }

    return 0;
}

/**
 * @brief Check for TLS protocol anomalies
 */
int
ips_tls_check_anomaly(void *parser_state, u8 *data, u32 len, u8 direction)
{
    ips_tls_parser_state_t *state = (ips_tls_parser_state_t *)parser_state;

    if (!state || !data || len < 5)
        return 0;

    /* Check for common TLS anomalies */

    /* 1. Invalid TLS record length */
    u16 record_len = (data[3] << 8) | data[4];
    if (record_len < 1 || record_len > 16384)
        return 1;

    /* 2. Invalid version */
    u8 major = data[1];
    u8 minor = data[2];
    if (!ips_tls_is_valid_version(major, minor))
        return 1;

    /* 3. Invalid content type */
    u8 content_type = data[0];
    if (content_type < 20 || content_type > 24)
        return 1;

    /* 4. Version downgrade attacks */
    if (state->version.major != 0xFF)
    {
        if (major < state->version.major ||
            (major == state->version.major && minor < state->version.minor))
        {
            return 1;  /* Potential version downgrade */
        }
    }

    /* 5. Suspicious handshake order */
    if (content_type == IPS_TLS_CONTENT_TYPE_HANDSHAKE && len > 5)
    {
        u8 handshake_type = data[5];
        if (direction == 0 && handshake_type == IPS_TLS_HANDSHAKE_SERVER_HELLO)
            return 1;  /* ServerHello from client */
        if (direction == 1 && handshake_type == IPS_TLS_HANDSHAKE_CLIENT_HELLO)
            return 1;  /* ClientHello from server */
    }

    return 0;
}

/**
 * @brief Get TLS metadata for logging
 */
int
ips_tls_get_metadata(void *parser_state, char *buffer, u32 buffer_len)
{
    ips_tls_parser_state_t *state = (ips_tls_parser_state_t *)parser_state;

    if (!state || !buffer || buffer_len < 64)
        return -1;

    int written = 0;

    /* Basic TLS info */
    written += snprintf(buffer + written, buffer_len - written,
                       "TLS %s",
                       ips_tls_version_to_string(state->version));

    /* Add cipher suite if known */
    if (state->selected_cipher_suite > 0)
    {
        const char *cipher_name = "Unknown";
        for (u32 i = 0; i < ARRAY_LEN(tls_cipher_suites); i++)
        {
            if (tls_cipher_suites[i].id == state->selected_cipher_suite)
            {
                cipher_name = tls_cipher_suites[i].name;
                break;
            }
        }
        written += snprintf(buffer + written, buffer_len - written,
                           " %s", cipher_name);
    }

    /* Add SNI if available */
    if (state->sni_length > 0)
    {
        written += snprintf(buffer + written, buffer_len - written,
                           " sni:%s", state->sni);
    }

    /* Add flags */
    if (state->flags & IPS_TLS_FLAG_RESUMPTION)
        written += snprintf(buffer + written, buffer_len - written, " resumed");
    if (state->flags & IPS_TLS_FLAG_ANOMALY)
        written += snprintf(buffer + written, buffer_len - written, " ANOMALY");

    return written;
}