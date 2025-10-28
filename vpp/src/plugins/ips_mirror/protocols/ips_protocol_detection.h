/*
 * ips_protocol_detection.h - VPP IPS Plugin Protocol Detection
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

#ifndef __IPS_PROTOCOL_DETECTION_H__
#define __IPS_PROTOCOL_DETECTION_H__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include "../session/ips_session.h"

/* Application Layer Protocol Types (following Suricata's approach) */
typedef enum
{
    IPS_ALPROTO_UNKNOWN = 0,
    IPS_ALPROTO_HTTP,
    IPS_ALPROTO_FTP,
    IPS_ALPROTO_SMTP,
    IPS_ALPROTO_TLS,          /* SSL/TLS */
    IPS_ALPROTO_SSH,
    IPS_ALPROTO_DNS,
    IPS_ALPROTO_DCERPC,
    IPS_ALPROTO_SMB,
    IPS_ALPROTO_NFS,
    IPS_ALPROTO_TFTP,
    IPS_ALPROTO_IKEV2,
    IPS_ALPROTO_KRB5,
    IPS_ALPROTO_NTP,
    IPS_ALPROTO_DHCP,
    IPS_ALPROTO_MODBUS,
    IPS_ALPROTO_ENIP,
    IPS_ALPROTO_DNP3,
    IPS_ALPROTO_MQTT,
    IPS_ALPROTO_WEBSOCKET,
    IPS_ALPROTO_MAX
} ips_alproto_t;

/* Protocol Detection State */
typedef enum
{
    IPS_PROTO_DETECT_IN_PROGRESS = 0,
    IPS_PROTO_DETECT_DONE,
    IPS_PROTO_DETECT_FAILED
} ips_proto_detect_state_t;

/* Protocol-specific parsing states */
typedef enum
{
    IPS_PROTO_STATE_NONE = 0,
    IPS_PROTO_STATE_INIT,
    IPS_PROTO_STATE_NEGOTIATING,
    IPS_PROTO_STATE_ESTABLISHED,
    IPS_PROTO_STATE_CLOSING,
    IPS_PROTO_STATE_ERROR
} ips_proto_state_t;

/* Protocol parsing flags */
typedef enum
{
    IPS_PROTO_FLAG_NONE = 0,
    IPS_PROTO_FLAG_ENCRYPTED = 0x01,
    IPS_PROTO_FLAG_COMPRESSED = 0x02,
    IPS_PROTO_FLAG_MULTIPLEXED = 0x04,
    IPS_PROTO_STATE_ANOMALY_DETECTED = 0x08
} ips_proto_flags_t;

/* Protocol Detection Context (per flow) */
typedef struct
{
    ips_alproto_t detected_protocol;
    ips_proto_detect_state_t state;

    /* Protocol-specific state */
    ips_proto_state_t proto_state;

    /* Detection confidence (0-100) */
    u8 confidence;

    /* Number of packets examined for detection */
    u16 packets_examined;

    /* Protocol-specific parser state */
    void *parser_state;

    /* Protocol parsing flags */
    ips_proto_flags_t flags;

    /* Last detected timestamp (for timeout) */
    f64 last_detection_time;

    /* Bytes processed for protocol analysis */
    u64 bytes_processed;

    /* Protocol-specific data counters */
    u32 packets_count[2];  /* [0]=client->server, [1]=server->client */

} ips_proto_detect_ctx_t;

/* Protocol Parser Interface */
typedef struct
{
    /* Protocol type */
    ips_alproto_t protocol;

    /* Protocol name */
    const char *name;

    /* Default ports (array, terminated by 0) */
    u16 *default_ports;

    /* Minimum bytes needed for reliable detection */
    u16 min_detect_len;

    /* Probe function - returns confidence (0-100) */
    u8 (*probe)(u8 *data, u32 len, u8 direction);

    /* Parse function - updates parser state and proto_state */
    int (*parse)(void *parser_state, u8 *data, u32 len, u8 direction,
                 ips_proto_state_t *proto_state, ips_proto_flags_t *flags);

    /* Get protocol-specific metadata */
    int (*get_metadata)(void *parser_state, char *buffer, u32 buffer_len);

    /* Check for protocol anomalies */
    int (*check_anomaly)(void *parser_state, u8 *data, u32 len, u8 direction);

    /* Create/initialize parser state */
    void *(*init_state)(void);

    /* Free parser state */
    void (*free_state)(void *parser_state);

    /* Protocol timeout in seconds (0 = no timeout) */
    u32 timeout_seconds;

} ips_proto_parser_t;


/**
 * @brief Initialize protocol detection module
 */
clib_error_t *ips_protocol_detection_init(void);

/**
 * @brief Detect application layer protocol
 * @param session Session context
 * @param b Packet buffer
 * @param l4_proto L4 protocol (TCP/UDP)
 * @param payload Pointer to application layer payload
 * @param payload_len Length of payload
 * @param direction 0=client->server, 1=server->client
 * @return Detected protocol or IPS_ALPROTO_UNKNOWN
 */
ips_alproto_t ips_detect_protocol(ips_session_t *session,
                                  vlib_buffer_t *b,
                                  u8 l4_proto,
                                  u8 *payload,
                                  u32 payload_len,
                                  u8 direction);

/**
 * @brief Get protocol detection context for a session
 */
ips_proto_detect_ctx_t *ips_get_proto_detect_ctx(ips_session_t *session);

/**
 * @brief Register a protocol parser
 */
int ips_register_protocol_parser(const ips_proto_parser_t *parser);

/**
 * @brief Get protocol name
 */
const char *ips_alproto_to_string(ips_alproto_t proto);

/**
 * @brief Perform protocol-specific inspection
 * @param session Session context
 * @param proto Detected protocol
 * @param payload Application payload
 * @param payload_len Payload length
 * @return 0=pass, 1=block
 */
int ips_protocol_inspect(ips_session_t *session,
                        ips_alproto_t proto,
                        u8 *payload,
                        u32 payload_len);

/**
 * @brief Update protocol parsing state with new packet data
 * @param session Session context
 * @param payload Application payload
 * @param payload_len Payload length
 * @param direction Packet direction
 * @return 0=success, -1=error
 */
int ips_protocol_update_state(ips_session_t *session,
                             u8 *payload,
                             u32 payload_len,
                             u8 direction);

/**
 * @brief Get protocol parsing state
 */
ips_proto_state_t ips_get_protocol_state(ips_session_t *session);

/**
 * @brief Check if protocol parsing detected anomalies
 */
int ips_protocol_has_anomalies(ips_session_t *session);

/**
 * @brief Get protocol-specific metadata
 */
int ips_get_protocol_metadata(ips_session_t *session,
                             char *buffer,
                             u32 buffer_len);

/**
 * @brief Cleanup protocol detection context for expired sessions
 */
void ips_protocol_cleanup_expired_sessions(f64 current_time);

/**
 * @brief Get protocol detection statistics
 */
void ips_protocol_get_stats(u64 *total_detections,
                           u64 *protocol_counts,
                           u32 *protocol_count_size);

#endif /* __IPS_PROTOCOL_DETECTION_H__ */

