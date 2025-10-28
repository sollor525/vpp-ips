/*
 * ips_protocol_detection.c - VPP IPS Plugin Protocol Detection Implementation
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/hash.h>

#include "../ips.h"
#include "../session/ips_session.h"
#include "../ips_logging.h"
#include "ips_protocol_detection.h"
#include "ips_http_parser.h"
#include "ips_tls_parser.h"
#include "ips_dns_parser.h"

/* Global protocol parser registry */
typedef struct
{
    /* Registered parsers by protocol type */
    ips_proto_parser_t *parsers[IPS_ALPROTO_MAX];

    /* Multi-port lookup table for each protocol */
    uword *port_to_proto_map;  /* hash: port -> protocol */

    /* Protocol detection context storage (per session)
     * Key: session_index (u32), Value: pointer to ips_proto_detect_ctx_t */
    uword *proto_ctx_by_session;  /* hash: session_index -> proto_detect_ctx */

    /* Statistics */
    u64 detections[IPS_ALPROTO_MAX];
    u64 total_detections;
    u64 detection_attempts;
    u64 detection_failures;
    u64 anomaly_detections;

    /* Configuration */
    u32 max_detection_packets;     /* Max packets to examine for detection */
    u32 session_timeout_seconds;   /* Session cleanup timeout */
    f64 last_cleanup_time;         /* Last cleanup timestamp */

} ips_proto_detect_main_t;

static ips_proto_detect_main_t ips_proto_detect_main;

/* Protocol name strings */
static const char *ips_alproto_strings[] = {
    [IPS_ALPROTO_UNKNOWN] = "unknown",
    [IPS_ALPROTO_HTTP] = "http",
    [IPS_ALPROTO_FTP] = "ftp",
    [IPS_ALPROTO_SMTP] = "smtp",
    [IPS_ALPROTO_TLS] = "tls",
    [IPS_ALPROTO_SSH] = "ssh",
    [IPS_ALPROTO_DNS] = "dns",
    [IPS_ALPROTO_DCERPC] = "dcerpc",
    [IPS_ALPROTO_SMB] = "smb",
    [IPS_ALPROTO_NFS] = "nfs",
    [IPS_ALPROTO_TFTP] = "tftp",
    [IPS_ALPROTO_IKEV2] = "ikev2",
    [IPS_ALPROTO_KRB5] = "krb5",
    [IPS_ALPROTO_NTP] = "ntp",
    [IPS_ALPROTO_DHCP] = "dhcp",
    [IPS_ALPROTO_MODBUS] = "modbus",
    [IPS_ALPROTO_ENIP] = "enip",
    [IPS_ALPROTO_DNP3] = "dnp3",
    [IPS_ALPROTO_MQTT] = "mqtt",
    [IPS_ALPROTO_WEBSOCKET] = "websocket",
};

/**
 * @brief HTTP protocol probe
 */
static u8
ips_probe_http(u8 *data, u32 len, u8 direction)
{
    return ips_http_probe(data, len, direction);
}

/**
 * @brief TLS/SSL protocol probe
 */
static u8
ips_probe_tls(u8 *data, u32 len, u8 direction)
{
    return ips_tls_probe(data, len, direction);
}

/**
 * @brief SSH protocol probe
 */
static u8
ips_probe_ssh(u8 *data, u32 len, u8 __clib_unused direction)
{
    if (!data || len < 4)
        return 0;
    
    /* SSH banner: "SSH-" */
    if (clib_memcmp(data, "SSH-", 4) == 0)
        return 95;
    
    return 0;
}

/**
 * @brief DNS protocol probe (UDP/TCP)
 */
static u8
ips_probe_dns(u8 *data, u32 len, u8 direction)
{
    return ips_dns_probe(data, len, direction);
}

/**
 * @brief FTP protocol probe
 */
static u8
ips_probe_ftp(u8 *data, u32 len, u8 direction)
{
    if (!data || len < 3)
        return 0;
    
    /* FTP responses start with 3-digit code */
    if (direction == 1 && len >= 3 &&
        data[0] >= '1' && data[0] <= '5' &&
        data[1] >= '0' && data[1] <= '9' &&
        data[2] >= '0' && data[2] <= '9')
        return 70;
    
    /* FTP commands */
    if (direction == 0 && (clib_memcmp(data, "USER", 4) == 0 ||
                          clib_memcmp(data, "PASS", 4) == 0 ||
                          clib_memcmp(data, "LIST", 4) == 0))
        return 80;
    
    return 0;
}

/**
 * @brief SMTP protocol probe
 */
static u8
ips_probe_smtp(u8 *data, u32 len, u8 direction)
{
    if (!data || len < 4)
        return 0;
    
    /* SMTP commands */
    if (direction == 0 && (clib_memcmp(data, "HELO", 4) == 0 ||
                          clib_memcmp(data, "EHLO", 4) == 0 ||
                          clib_memcmp(data, "MAIL", 4) == 0 ||
                          clib_memcmp(data, "RCPT", 4) == 0))
        return 80;
    
    /* SMTP responses */
    if (direction == 1 && len >= 3 &&
        data[0] >= '2' && data[0] <= '5' &&
        data[1] >= '0' && data[1] <= '9' &&
        data[2] >= '0' && data[2] <= '9')
        return 70;
    
    return 0;
}

/* Default port arrays for each protocol */
static u16 http_ports[] = {80, 8080, 8000, 8008, 3000, 8081, 8888, 0};
static u16 https_ports[] = {443, 8443, 9443, 0};
static u16 ssh_ports[] = {22, 2222, 2022, 0};
static u16 dns_ports[] = {53, 5353, 0};
static u16 ftp_ports[] = {21, 2121, 0};
static u16 smtp_ports[] = {25, 587, 2525, 0};

/* Protocol parsers registration */
static ips_proto_parser_t http_parser = {
    .protocol = IPS_ALPROTO_HTTP,
    .name = "http",
    .default_ports = http_ports,
    .min_detect_len = 4,
    .probe = ips_probe_http,
    .parse = ips_http_parse,
    .get_metadata = ips_http_get_metadata,
    .check_anomaly = ips_http_check_anomaly,
    .init_state = ips_http_parser_init,
    .free_state = ips_http_parser_free,
    .timeout_seconds = 300,
};

static ips_proto_parser_t tls_parser = {
    .protocol = IPS_ALPROTO_TLS,
    .name = "tls",
    .default_ports = https_ports,
    .min_detect_len = 5,
    .probe = ips_probe_tls,
    .parse = ips_tls_parse,
    .get_metadata = ips_tls_get_metadata,
    .check_anomaly = ips_tls_check_anomaly,
    .init_state = ips_tls_parser_init,
    .free_state = ips_tls_parser_free,
    .timeout_seconds = 3600,
};

static ips_proto_parser_t ssh_parser = {
    .protocol = IPS_ALPROTO_SSH,
    .name = "ssh",
    .default_ports = ssh_ports,
    .min_detect_len = 4,
    .probe = ips_probe_ssh,
    .timeout_seconds = 1800,
};

static ips_proto_parser_t dns_parser = {
    .protocol = IPS_ALPROTO_DNS,
    .name = "dns",
    .default_ports = dns_ports,
    .min_detect_len = 12,
    .probe = ips_probe_dns,
    .parse = ips_dns_parse,
    .get_metadata = ips_dns_get_metadata,
    .check_anomaly = ips_dns_check_anomaly,
    .init_state = ips_dns_parser_init,
    .free_state = ips_dns_parser_free,
    .timeout_seconds = 60,
};

static ips_proto_parser_t ftp_parser = {
    .protocol = IPS_ALPROTO_FTP,
    .name = "ftp",
    .default_ports = ftp_ports,
    .min_detect_len = 3,
    .probe = ips_probe_ftp,
    .timeout_seconds = 1800,
};

static ips_proto_parser_t smtp_parser = {
    .protocol = IPS_ALPROTO_SMTP,
    .name = "smtp",
    .default_ports = smtp_ports,
    .min_detect_len = 4,
    .probe = ips_probe_smtp,
    .timeout_seconds = 600,
};

/**
 * @brief Register a protocol parser
 */
int
ips_register_protocol_parser(const ips_proto_parser_t *parser)
{
    ips_proto_detect_main_t *pdm = &ips_proto_detect_main;

    if (!parser || parser->protocol >= IPS_ALPROTO_MAX)
        return -1;

    pdm->parsers[parser->protocol] = (ips_proto_parser_t *)parser;

    /* Register all default ports */
    if (parser->default_ports)
    {
        for (u32 i = 0; parser->default_ports[i] != 0; i++)
        {
            u16 port = parser->default_ports[i];
            hash_set(pdm->port_to_proto_map, port, parser->protocol);
        }
    }

    return 0;
}

/**
 * @brief Initialize protocol detection module
 */
clib_error_t *
ips_protocol_detection_init(void)
{
    ips_proto_detect_main_t *pdm = &ips_proto_detect_main;

    clib_memset(pdm, 0, sizeof(*pdm));
    pdm->port_to_proto_map = hash_create(0, sizeof(uword));
    pdm->proto_ctx_by_session = hash_create(0, sizeof(uword));

    /* Initialize configuration */
    pdm->max_detection_packets = 10;
    pdm->session_timeout_seconds = 3600;
    pdm->last_cleanup_time = 0;

    /* Register built-in protocol parsers */
    ips_register_protocol_parser(&http_parser);
    ips_register_protocol_parser(&tls_parser);
    ips_register_protocol_parser(&ssh_parser);
    ips_register_protocol_parser(&dns_parser);
    ips_register_protocol_parser(&ftp_parser);
    ips_register_protocol_parser(&smtp_parser);

    return 0;
}

/**
 * @brief Get protocol name
 */
const char *
ips_alproto_to_string(ips_alproto_t proto)
{
    if (proto < IPS_ALPROTO_MAX)
        return ips_alproto_strings[proto];
    return "invalid";
}

/**
 * @brief Detect application layer protocol
 */
ips_alproto_t
ips_detect_protocol(ips_session_t *session,
                   vlib_buffer_t __clib_unused *b,
                   u8 __clib_unused l4_proto,
                   u8 *payload,
                   u32 payload_len,
                   u8 direction)
{
    ips_proto_detect_main_t *pdm = &ips_proto_detect_main;
    ips_proto_detect_ctx_t *ctx;

    if (!session || !payload || payload_len == 0)
        return IPS_ALPROTO_UNKNOWN;

    pdm->detection_attempts++;

    /* Get or create protocol detection context for this session */
    u32 session_key = session->session_index;
    uword *p = hash_get(pdm->proto_ctx_by_session, session_key);

    if (p)
    {
        ctx = (ips_proto_detect_ctx_t *)(p[0]);
    }
    else
    {
        ctx = clib_mem_alloc(sizeof(ips_proto_detect_ctx_t));
        clib_memset(ctx, 0, sizeof(*ctx));
        ctx->proto_state = IPS_PROTO_STATE_INIT;
        ctx->last_detection_time = vlib_time_now(vlib_get_main());
        hash_set(pdm->proto_ctx_by_session, session_key, (uword)ctx);
    }

    /* Update packet counters */
    if (direction < 2)
        ctx->packets_count[direction]++;

    ctx->bytes_processed += payload_len;
    ctx->last_detection_time = vlib_time_now(vlib_get_main());

    /* If protocol already detected with high confidence, return it */
    if (ctx->state == IPS_PROTO_DETECT_DONE && ctx->confidence >= 90)
    {
        return ctx->detected_protocol;
    }

    /* Limit detection attempts */
    if (ctx->packets_examined >= pdm->max_detection_packets)
    {
        ctx->state = IPS_PROTO_DETECT_FAILED;
        pdm->detection_failures++;
        return IPS_ALPROTO_UNKNOWN;
    }

    ctx->packets_examined++;

    /* Try port-based hint first */
    u16 port = direction == 0 ? session->dst_port : session->src_port;
    uword *port_p = hash_get(pdm->port_to_proto_map, port);
    ips_alproto_t hint_proto = port_p ? (ips_alproto_t)port_p[0] : IPS_ALPROTO_UNKNOWN;

    /* Probe all registered parsers */
    u8 best_confidence = 0;
    ips_alproto_t best_proto = IPS_ALPROTO_UNKNOWN;
    ips_proto_parser_t *best_parser = NULL;

    for (u32 i = 1; i < IPS_ALPROTO_MAX; i++)
    {
        ips_proto_parser_t *parser = pdm->parsers[i];
        if (!parser || !parser->probe)
            continue;

        /* Skip if payload is too small for reliable detection */
        if (payload_len < parser->min_detect_len)
            continue;

        /* Give port-hinted protocol a boost */
        u8 confidence = parser->probe(payload, payload_len, direction);
        if (i == hint_proto)
            confidence = clib_min(confidence + 10, 100);

        if (confidence > best_confidence)
        {
            best_confidence = confidence;
            best_proto = i;
            best_parser = parser;
        }
    }

    /* Update detection context */
    if (best_confidence > ctx->confidence)
    {
        ctx->detected_protocol = best_proto;
        ctx->confidence = best_confidence;

        /* Initialize parser state if we have a new best protocol */
        if (best_parser && best_parser->init_state && !ctx->parser_state)
        {
            ctx->parser_state = best_parser->init_state();
        }

        if (best_confidence >= 90)
        {
            ctx->state = IPS_PROTO_DETECT_DONE;
            ctx->proto_state = IPS_PROTO_STATE_ESTABLISHED;
            pdm->detections[best_proto]++;
            pdm->total_detections++;
        }
        else
        {
            ctx->state = IPS_PROTO_DETECT_IN_PROGRESS;
        }
    }

    return ctx->detected_protocol;
}

/**
 * @brief Get protocol detection context for a session
 */
ips_proto_detect_ctx_t *
ips_get_proto_detect_ctx(ips_session_t *session)
{
    ips_proto_detect_main_t *pdm = &ips_proto_detect_main;
    
    if (!session)
        return NULL;
    
    u32 session_key = session->session_index;
    uword *p = hash_get(pdm->proto_ctx_by_session, session_key);
    
    return p ? (ips_proto_detect_ctx_t *)(p[0]) : NULL;
}

/**
 * @brief Update protocol parsing state with new packet data
 */
int
ips_protocol_update_state(ips_session_t *session,
                         u8 *payload,
                         u32 payload_len,
                         u8 direction)
{
    ips_proto_detect_main_t *pdm = &ips_proto_detect_main;
    ips_proto_detect_ctx_t *ctx;

    if (!session || !payload)
        return -1;

    ctx = ips_get_proto_detect_ctx(session);
    if (!ctx || ctx->detected_protocol == IPS_ALPROTO_UNKNOWN)
        return -1;

    ips_proto_parser_t *parser = pdm->parsers[ctx->detected_protocol];
    if (!parser || !parser->parse)
        return 0;

    /* Call protocol-specific parser */
    int result = parser->parse(ctx->parser_state, payload, payload_len, direction,
                               &ctx->proto_state, &ctx->flags);

    /* Check for anomalies if parser supports it */
    if (parser->check_anomaly)
    {
        if (parser->check_anomaly(ctx->parser_state, payload, payload_len, direction))
        {
            ctx->flags |= IPS_PROTO_STATE_ANOMALY_DETECTED;
            pdm->anomaly_detections++;
        }
    }

    return result;
}

/**
 * @brief Get protocol parsing state
 */
ips_proto_state_t
ips_get_protocol_state(ips_session_t *session)
{
    ips_proto_detect_ctx_t *ctx = ips_get_proto_detect_ctx(session);
    return ctx ? ctx->proto_state : IPS_PROTO_STATE_NONE;
}

/**
 * @brief Check if protocol parsing detected anomalies
 */
int
ips_protocol_has_anomalies(ips_session_t *session)
{
    ips_proto_detect_ctx_t *ctx = ips_get_proto_detect_ctx(session);
    return ctx ? (ctx->flags & IPS_PROTO_STATE_ANOMALY_DETECTED) != 0 : 0;
}

/**
 * @brief Get protocol-specific metadata
 */
int
ips_get_protocol_metadata(ips_session_t *session,
                         char *buffer,
                         u32 buffer_len)
{
    ips_proto_detect_main_t *pdm = &ips_proto_detect_main;
    ips_proto_detect_ctx_t *ctx;

    if (!session || !buffer || buffer_len == 0)
        return -1;

    ctx = ips_get_proto_detect_ctx(session);
    if (!ctx || ctx->detected_protocol == IPS_ALPROTO_UNKNOWN)
        return -1;

    ips_proto_parser_t *parser = pdm->parsers[ctx->detected_protocol];
    if (!parser || !parser->get_metadata)
        return -1;

    return parser->get_metadata(ctx->parser_state, buffer, buffer_len);
}

/**
 * @brief Cleanup protocol detection context for expired sessions
 */
void
ips_protocol_cleanup_expired_sessions(f64 current_time)
{
    ips_proto_detect_main_t *pdm = &ips_proto_detect_main;
    u32 cleanup_count = 0;

    /* Run cleanup every 60 seconds */
    if (current_time - pdm->last_cleanup_time < 60.0)
        return;

    pdm->last_cleanup_time = current_time;

    /* Iterate through all sessions using VPP hash API */
    hash_pair_t *p;
    hash_foreach_pair(p, pdm->proto_ctx_by_session, ({
        u32 session_key = p->key;
        ips_proto_detect_ctx_t *ctx = (ips_proto_detect_ctx_t *)p->value[0];

        /* Check if session is expired */
        f64 age = current_time - ctx->last_detection_time;
        if (age > pdm->session_timeout_seconds)
        {
            /* Free parser state if exists */
            if (ctx->parser_state)
            {
                ips_proto_parser_t *parser = pdm->parsers[ctx->detected_protocol];
                if (parser && parser->free_state)
                    parser->free_state(ctx->parser_state);
            }

            /* Free context and remove from hash */
            clib_mem_free(ctx);
            hash_unset(pdm->proto_ctx_by_session, session_key);
            cleanup_count++;
        }
    }));

    if (cleanup_count > 0)
    {
        ips_log_system_async(IPS_LOG_LEVEL_INFO,
                            "Cleaned up %u expired protocol detection contexts",
                            cleanup_count);
    }
}

/**
 * @brief Get protocol detection statistics
 */
void
ips_protocol_get_stats(u64 *total_detections,
                      u64 *protocol_counts,
                      u32 *protocol_count_size)
{
    ips_proto_detect_main_t *pdm = &ips_proto_detect_main;

    if (total_detections)
        *total_detections = pdm->total_detections;

    if (protocol_counts && protocol_count_size)
    {
        u32 copy_size = clib_min(*protocol_count_size, IPS_ALPROTO_MAX);
        clib_memcpy(protocol_counts, pdm->detections, copy_size * sizeof(u64));
        *protocol_count_size = copy_size;
    }
}

/**
 * @brief Perform protocol-specific inspection
 */
int
ips_protocol_inspect(ips_session_t *session,
                    ips_alproto_t proto,
                    u8 *payload,
                    u32 payload_len)
{
    /* Update protocol state first */
    ips_protocol_update_state(session, payload, payload_len, 0);

    /* Check for anomalies */
    if (ips_protocol_has_anomalies(session))
    {
        ips_log_system_async(IPS_LOG_LEVEL_INFO,
                            "Protocol anomaly detected in session %u",
                            session->session_index);
        return 1;  /* Block on anomaly */
    }

    /* TODO: Implement protocol-specific rule matching */
    /* This will integrate with the Suricata rules engine */
    return 0;  /* Pass for now */
}

