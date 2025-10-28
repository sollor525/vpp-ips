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
#include "ips_protocol_detection.h"

/* Global protocol parser registry */
typedef struct
{
    /* Registered parsers by protocol type */
    ips_proto_parser_t *parsers[IPS_ALPROTO_MAX];
    
    /* Port-based lookup (quick hint) */
    uword *port_to_proto_map;  /* hash: port -> protocol */
    
    /* Protocol detection context storage (per session)
     * Key: session_index (u32), Value: pointer to ips_proto_detect_ctx_t */
    uword *proto_ctx_by_session;  /* hash: session_index -> proto_detect_ctx */
    
    /* Statistics */
    u64 detections[IPS_ALPROTO_MAX];
    u64 total_detections;
    
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
ips_probe_http(u8 *data, u32 len, u8 __clib_unused direction)
{
    if (!data || len < 4)
        return 0;
    
    /* Check for HTTP methods */
    if (len >= 4 && (clib_memcmp(data, "GET ", 4) == 0 ||
                     clib_memcmp(data, "POST", 4) == 0 ||
                     clib_memcmp(data, "HEAD", 4) == 0 ||
                     clib_memcmp(data, "PUT ", 4) == 0))
        return 95;  /* High confidence */
    
    /* Check for HTTP response */
    if (len >= 5 && clib_memcmp(data, "HTTP/", 5) == 0)
        return 95;
    
    return 0;
}

/**
 * @brief TLS/SSL protocol probe
 */
static u8
ips_probe_tls(u8 *data, u32 len, u8 __clib_unused direction)
{
    if (!data || len < 3)
        return 0;
    
    /* TLS handshake: 0x16 (handshake), version (0x03 0x00 to 0x03 0x03) */
    if (data[0] == 0x16 && data[1] == 0x03 && data[2] <= 0x03)
        return 90;
    
    /* TLS application data */
    if (data[0] == 0x17 && data[1] == 0x03 && data[2] <= 0x03)
        return 85;
    
    return 0;
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
ips_probe_dns(u8 *data, u32 len, u8 __clib_unused direction)
{
    if (!data || len < 12)
        return 0;
    
    /* Basic DNS header validation */
    u16 __clib_unused flags = (data[2] << 8) | data[3];
    u16 qdcount = (data[4] << 8) | data[5];
    
    /* Check QR bit and question count */
    if (qdcount > 0 && qdcount < 10)
        return 70;  /* Moderate confidence */
    
    return 0;
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

/* Protocol parsers registration */
static ips_proto_parser_t http_parser = {
    .protocol = IPS_ALPROTO_HTTP,
    .name = "http",
    .default_port = 80,
    .probe = ips_probe_http,
};

static ips_proto_parser_t tls_parser = {
    .protocol = IPS_ALPROTO_TLS,
    .name = "tls",
    .default_port = 443,
    .probe = ips_probe_tls,
};

static ips_proto_parser_t ssh_parser = {
    .protocol = IPS_ALPROTO_SSH,
    .name = "ssh",
    .default_port = 22,
    .probe = ips_probe_ssh,
};

static ips_proto_parser_t dns_parser = {
    .protocol = IPS_ALPROTO_DNS,
    .name = "dns",
    .default_port = 53,
    .probe = ips_probe_dns,
};

static ips_proto_parser_t ftp_parser = {
    .protocol = IPS_ALPROTO_FTP,
    .name = "ftp",
    .default_port = 21,
    .probe = ips_probe_ftp,
};

static ips_proto_parser_t smtp_parser = {
    .protocol = IPS_ALPROTO_SMTP,
    .name = "smtp",
    .default_port = 25,
    .probe = ips_probe_smtp,
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
    
    /* Register port hint if specified */
    if (parser->default_port > 0)
    {
        hash_set(pdm->port_to_proto_map, parser->default_port, parser->protocol);
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
        hash_set(pdm->proto_ctx_by_session, session_key, (uword)ctx);
    }
    
    /* If protocol already detected with high confidence, return it */
    if (ctx->state == IPS_PROTO_DETECT_DONE && ctx->confidence >= 90)
    {
        return ctx->detected_protocol;
    }
    
    /* Limit detection attempts */
    if (ctx->packets_examined >= 10)
    {
        ctx->state = IPS_PROTO_DETECT_FAILED;
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
    
    for (u32 i = 1; i < IPS_ALPROTO_MAX; i++)
    {
        ips_proto_parser_t *parser = pdm->parsers[i];
        if (!parser || !parser->probe)
            continue;
        
        /* Give port-hinted protocol a boost */
        u8 confidence = parser->probe(payload, payload_len, direction);
        if (i == hint_proto)
            confidence = clib_min(confidence + 10, 100);
        
        if (confidence > best_confidence)
        {
            best_confidence = confidence;
            best_proto = i;
        }
    }
    
    /* Update detection context */
    if (best_confidence > ctx->confidence)
    {
        ctx->detected_protocol = best_proto;
        ctx->confidence = best_confidence;
        
        if (best_confidence >= 90)
        {
            ctx->state = IPS_PROTO_DETECT_DONE;
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
 * @brief Perform protocol-specific inspection
 */
int
ips_protocol_inspect(ips_session_t __clib_unused *session,
                    ips_alproto_t __clib_unused proto,
                    u8 __clib_unused *payload,
                    u32 __clib_unused payload_len)
{
    /* TODO: Implement protocol-specific deep inspection */
    /* This will call protocol-specific rule matching */
    return 0;  /* Pass for now */
}

