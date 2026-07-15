#include <canard.h>

#define RAPIDHASH_COMPACT
#include <rapidhash.h>

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SUBJECT_ID_MODULUS 57203U
#define SUBJECT_ID_PINNED_MAX 8191U
#define GOSSIP_FIRST 65395U
#define GOSSIP_COUNT 140U
#define BROADCAST_SUBJECT 65535U
#define HEADER_SIZE 24U
#define CAN_EFF_FLAG 0x80000000U
#define CANFD_FDF 0x04U

static FILE*       capture;
static uint32_t    packet_index;
static uint32_t    timestamp_us;
static const char* case_name;
static FILE*       manifest;
static bool        corrupt_final_crc;

static void put_u16_le(FILE* const out, const uint16_t value)
{
    fputc((int)(value & 0xFFU), out);
    fputc((int)(value >> 8U), out);
}

static void put_u32_le(FILE* const out, const uint32_t value)
{
    for (size_t i = 0; i < 4; i++) {
        fputc((int)((value >> (8U * i)) & 0xFFU), out);
    }
}

static void put_u32_be(FILE* const out, const uint32_t value)
{
    for (size_t i = 0; i < 4; i++) {
        fputc((int)((value >> (24U - (8U * i))) & 0xFFU), out);
    }
}

static void pcap_open(const char* const path)
{
    capture = fopen(path, "wb");
    assert(capture != NULL);
    packet_index = 0U;
    put_u32_le(capture, UINT32_C(0xA1B2C3D4));
    put_u16_le(capture, 2U);
    put_u16_le(capture, 4U);
    put_u32_le(capture, 0U);
    put_u32_le(capture, 0U);
    put_u32_le(capture, 72U);
    put_u32_le(capture, 227U); // LINKTYPE_CAN_SOCKETCAN
}

static void pcap_close(void)
{
    assert(fclose(capture) == 0);
    capture = NULL;
}

static void write_socketcan(const bool fd, const uint32_t socketcan_id, const size_t size, const void* const data)
{
    assert((size <= 64U) && ((size <= 8U) || fd));
    const uint32_t captured_size = fd ? 72U : 16U;
    put_u32_le(capture, 1U);
    put_u32_le(capture, timestamp_us);
    put_u32_le(capture, captured_size);
    put_u32_le(capture, captured_size);
    put_u32_be(capture, socketcan_id);
    fputc((int)size, capture);
    fputc(fd ? CANFD_FDF : 0, capture);
    fputc(0, capture);
    fputc(0, capture);
    const unsigned char* const bytes = (const unsigned char*)data;
    for (size_t i = 0; i < size; i++) {
        unsigned char value = bytes[i];
        if (corrupt_final_crc && (size >= 3U) && ((bytes[size - 1U] & 0xC0U) == 0x40U) && (i == size - 2U)) {
            value ^= 0x80U;
            corrupt_final_crc = false;
        }
        fputc(value, capture);
    }
    for (size_t i = size; i < (fd ? 64U : 8U); i++) {
        fputc(0, capture);
    }
    packet_index++;
    timestamp_us += 1000U;
}

static void write_frame(const bool fd, const uint32_t can_id, const size_t size, const void* const data)
{
    write_socketcan(fd, can_id | CAN_EFF_FLAG, size, data);
}

static void* mem_alloc(const canard_mem_t memory, const size_t size)
{
    (void)memory;
    return malloc(size);
}

static void mem_free(const canard_mem_t memory, const size_t size, void* const pointer)
{
    (void)memory;
    (void)size;
    free(pointer);
}

static canard_us_t can_now(const canard_t* const canard)
{
    (void)canard;
    return 0;
}

static bool can_tx(canard_t* const      canard,
                   void* const          user_context,
                   const canard_us_t    deadline,
                   const uint_least8_t  iface_index,
                   const bool           fd,
                   const uint32_t       extended_can_id,
                   const canard_bytes_t data)
{
    (void)canard;
    (void)user_context;
    (void)deadline;
    assert(iface_index == 0U);
    write_frame(fd, extended_can_id, data.size, data.data);
    return true;
}

static const canard_mem_vtable_t memory_vtable = { .free = mem_free, .alloc = mem_alloc };
static const canard_vtable_t     canard_vtable  = { .now = can_now, .tx = can_tx, .filter = NULL };

static void le32(unsigned char* const out, const uint32_t value)
{
    for (size_t i = 0; i < 4U; i++) {
        out[i] = (unsigned char)((value >> (8U * i)) & 0xFFU);
    }
}

static void le48(unsigned char* const out, const uint64_t value)
{
    for (size_t i = 0; i < 6U; i++) {
        out[i] = (unsigned char)((value >> (8U * i)) & 0xFFU);
    }
}

static void le64(unsigned char* const out, const uint64_t value)
{
    for (size_t i = 0; i < 8U; i++) {
        out[i] = (unsigned char)((value >> (8U * i)) & 0xFFU);
    }
}

static uint16_t subject_id(const uint64_t hash, const uint32_t evictions)
{
    if (evictions >= UINT32_C(0xFFFFE000)) {
        return (uint16_t)(UINT32_MAX - evictions);
    }
    const uint64_t h = hash % SUBJECT_ID_MODULUS;
    const uint64_t e = evictions % SUBJECT_ID_MODULUS;
    return (uint16_t)(SUBJECT_ID_PINNED_MAX + 1U + ((h + ((e * e) % SUBJECT_ID_MODULUS)) % SUBJECT_ID_MODULUS));
}

static void make_message_header(unsigned char* const out,
                                const uint8_t              type,
                                const int8_t               lage,
                                const uint32_t             evictions,
                                const uint64_t             hash,
                                const uint64_t             tag)
{
    memset(out, 0, HEADER_SIZE);
    out[0] = type;
    out[3] = (unsigned char)lage;
    le32(&out[4], evictions);
    le64(&out[8], hash);
    le64(&out[16], tag);
}

static void make_ack_header(unsigned char* const out, const uint8_t type, const uint64_t hash, const uint64_t tag)
{
    memset(out, 0, HEADER_SIZE);
    out[0] = type;
    le64(&out[8], hash);
    le64(&out[16], tag);
}

static void make_response_header(unsigned char* const out,
                                 const uint8_t              type,
                                 const uint8_t              response_tag,
                                 const uint64_t             sequence,
                                 const uint64_t             hash,
                                 const uint64_t             message_tag)
{
    memset(out, 0, HEADER_SIZE);
    out[0] = type;
    out[1] = response_tag;
    le48(&out[2], sequence);
    le64(&out[8], hash);
    le64(&out[16], message_tag);
}

static void poll_all(canard_t* const canard)
{
    while (canard_pending_ifaces(canard) != 0U) {
        canard_poll(canard, 1U);
    }
    fprintf(manifest, "%s\t%u\n", case_name, packet_index);
}

static canard_bytes_chain_t payload(const void* const data, const size_t size)
{
    return (canard_bytes_chain_t){ .bytes = { .size = size, .data = data }, .next = NULL };
}

static void emit_16(canard_t* const canard,
                    const char* const name,
                    const bool fd,
                    const uint16_t sid,
                    const uint8_t tid,
                    const void* const data,
                    const size_t size)
{
    case_name     = name;
    canard->tx.fd = fd;
    assert(canard_publish_16b(canard, 1000000, 1U, canard_prio_nominal, sid, tid, payload(data, size), NULL));
    poll_all(canard);
}

static void emit_request(canard_t* const canard,
                         const char* const name,
                         const bool fd,
                         const uint16_t service,
                         const uint8_t destination,
                         const uint8_t tid,
                         const void* const data,
                         const size_t size)
{
    case_name     = name;
    canard->tx.fd = fd;
    assert(canard_request(canard, 1000000, canard_prio_high, service, destination, tid, payload(data, size), NULL));
    poll_all(canard);
}

static void emit_response(canard_t* const canard,
                          const char* const name,
                          const bool fd,
                          const uint16_t service,
                          const uint8_t destination,
                          const uint8_t tid,
                          const void* const data,
                          const size_t size)
{
    case_name     = name;
    canard->tx.fd = fd;
    assert(canard_respond(canard, 1000000, canard_prio_low, service, destination, tid, payload(data, size), NULL));
    poll_all(canard);
}

static void generate_valid(canard_t* const canard)
{
    static const char topic[] = "plant/temperature";
    const uint64_t hash = rapidhash(topic, sizeof(topic) - 1U);
    const uint16_t sid  = subject_id(hash, 0U);
    unsigned char buffer[256];

    make_message_header(buffer, 0U, -1, 0U, hash, UINT64_C(0x1122334455667788));
    memcpy(&buffer[24], "abc", 3U);
    emit_16(canard, "msg_be_fd_single", true, sid, 0U, buffer, 27U);

    make_message_header(buffer, 1U, 4, 0U, hash, UINT64_C(0x8877665544332211));
    for (size_t i = 24U; i < 154U; i++) buffer[i] = (unsigned char)i;
    emit_16(canard, "msg_rel_classic_multi", false, sid, 31U, buffer, 154U);

    make_ack_header(buffer, 2U, hash, UINT64_C(0x8877665544332211));
    buffer[1] = 0xAAU;
    buffer[2] = 0xBBU;
    buffer[3] = 0xCCU; // Void bytes are ignored by receivers.
    emit_request(canard, "msg_ack", true, 511U, 7U, 1U, buffer, 24U);
    buffer[0] = 3U;
    emit_request(canard, "msg_nack", true, 511U, 7U, 2U, buffer, 24U);

    for (uint8_t type = 4U; type <= 7U; type++) {
        make_response_header(buffer, type, (uint8_t)(0xA0U + type), UINT64_C(0x010203040506), hash,
                             UINT64_C(0x1122334455667788));
        size_t size = 24U;
        if (type <= 5U) {
            memcpy(&buffer[24], "response", 8U);
            size += 8U;
        }
        static const char* const names[] = { "rsp_be", "rsp_rel", "rsp_ack", "rsp_nack" };
        emit_request(canard, names[type - 4U], true, 511U, 7U, type, buffer, size);
    }

    memset(buffer, 0, sizeof(buffer));
    buffer[0] = 8U;
    buffer[3] = 2U;
    le64(&buffer[8], hash);
    le32(&buffer[16], 0U);
    buffer[23] = (unsigned char)(sizeof(topic) - 1U);
    memcpy(&buffer[24], topic, sizeof(topic) - 1U);
    emit_16(canard, "gossip_broadcast", true, BROADCAST_SUBJECT, 8U, buffer, 24U + sizeof(topic) - 1U);
    emit_16(canard, "gossip_shard", true, (uint16_t)(GOSSIP_FIRST + (hash % GOSSIP_COUNT)), 9U, buffer,
            24U + sizeof(topic) - 1U);

    static const char pattern[] = "plant/*";
    memset(buffer, 0, sizeof(buffer));
    buffer[0]  = 9U;
    buffer[23] = (unsigned char)(sizeof(pattern) - 1U);
    memcpy(&buffer[24], pattern, sizeof(pattern) - 1U);
    emit_16(canard, "scout", true, BROADCAST_SUBJECT, 10U, buffer, 24U + sizeof(pattern) - 1U);

    for (size_t i = 0; i < 80U; i++) buffer[i] = (unsigned char)(0xC0U + i);
    case_name     = "v10_message_multi";
    canard->tx.fd = false;
    assert(canard_publish_13b(canard, 1000000, 1U, canard_prio_fast, 1234U, 30U, payload(buffer, 80U), NULL));
    poll_all(canard);

    memcpy(buffer, "legacy request", 14U);
    emit_request(canard, "v10_service_request", false, 430U, 21U, 11U, buffer, 14U);
    memcpy(buffer, "legacy response", 15U);
    emit_response(canard, "v10_service_response", false, 430U, 21U, 12U, buffer, 15U);

    const unsigned char anonymous[] = { 0xAAU, 0xBBU, 0xCCU, 0xE5U };
    case_name = "v10_anonymous";
    write_frame(false, (UINT32_C(4) << 26U) | (UINT32_C(1) << 24U) | (UINT32_C(3) << 21U) |
                       (UINT32_C(321) << 8U) | 0x55U,
                sizeof(anonymous), anonymous);
    fprintf(manifest, "%s\t%u\n", case_name, packet_index);

    const uint64_t pinned_hash = rapidhash("pinned/topic", 12U);
    make_message_header(buffer, 0U, -1, UINT32_MAX - 42U, pinned_hash, UINT64_C(0x42));
    emit_16(canard, "pinned_message", true, 42U, 11U, buffer, 24U);

    const uint64_t boundary_hash = rapidhash("boundary/topic", 14U);
    make_message_header(buffer, 0U, 35, SUBJECT_ID_MODULUS - 1U, boundary_hash, UINT64_C(0xDEADBEEF));
    emit_16(canard, "modulus_boundary", true, subject_id(boundary_hash, SUBJECT_ID_MODULUS - 1U), 12U, buffer, 24U);

    char long_name[130];
    memcpy(long_name, "long/", 5U);
    memset(&long_name[5], 'x', sizeof(long_name) - 5U);
    const uint64_t long_hash = rapidhash(long_name, sizeof(long_name));
    memset(buffer, 0, sizeof(buffer));
    buffer[0]  = 8U;
    buffer[3]  = 1U;
    le64(&buffer[8], long_hash);
    buffer[23] = (unsigned char)sizeof(long_name);
    memcpy(&buffer[24], long_name, sizeof(long_name));
    emit_16(canard, "gossip_long_name", true, BROADCAST_SUBJECT, 13U, buffer, 24U + sizeof(long_name));
}

static void generate_invalid(canard_t* const canard)
{
    unsigned char buffer[160];
    const uint64_t hash = rapidhash("bad/topic", 9U);
    const uint16_t sid  = subject_id(hash, 0U);

    memset(buffer, 0, sizeof(buffer));
    buffer[0] = 0U;
    const unsigned char bad_toggle[25] = {
        0U, 0U, 0U, 0xFFU, 0U, 0U, 0U, 0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U,
        9U, 10U, 11U, 12U, 13U, 14U, 15U, 16U, 0xC1U,
    };
    case_name = "bad_start_toggle";
    write_frame(true, (UINT32_C(4) << 26U) | ((uint32_t)sid << 8U) | (UINT32_C(1) << 7U) | 42U,
                sizeof(bad_toggle), bad_toggle);
    fprintf(manifest, "%s\t%u\n", case_name, packet_index);

    const unsigned char short_header[] = { 0U, 1U, 2U, 0xE2U };
    case_name = "short_session";
    write_frame(false, (UINT32_C(4) << 26U) | ((uint32_t)sid << 8U) | (UINT32_C(1) << 7U) | 42U,
                sizeof(short_header), short_header);
    fprintf(manifest, "%s\t%u\n", case_name, packet_index);

    make_message_header(buffer, 0U, 36, 0U, hash, 1U);
    buffer[2] = 1U;
    emit_16(canard, "bad_message_fields", true, (uint16_t)(sid + 1U), 3U, buffer, 24U);

    make_message_header(buffer, 0U, 0, 0U, hash, 2U);
    for (size_t i = 24U; i < 150U; i++) buffer[i] = (unsigned char)i;
    corrupt_final_crc = true;
    emit_16(canard, "bad_crc", true, sid, 4U, buffer, 150U);
    assert(!corrupt_final_crc);

    const unsigned char orphan[] = { 1U, 2U, 3U, 0x61U };
    case_name = "orphan_end";
    write_frame(false, (UINT32_C(4) << 26U) | ((uint32_t)sid << 8U) | (UINT32_C(1) << 7U) | 42U,
                sizeof(orphan), orphan);
    fprintf(manifest, "%s\t%u\n", case_name, packet_index);

    memset(buffer, 0, 24U);
    buffer[0] = 200U;
    emit_16(canard, "unknown_session_type", true, sid, 5U, buffer, 24U);

    static const char wrong_name[] = "//bad//name/";
    memset(buffer, 0, sizeof(buffer));
    buffer[0]  = 8U;
    buffer[3]  = 0xFFU;
    le64(&buffer[8], hash);
    buffer[23] = (unsigned char)(sizeof(wrong_name) - 1U);
    memcpy(&buffer[24], wrong_name, sizeof(wrong_name) - 1U);
    emit_16(canard, "bad_gossip_name", true, (uint16_t)(GOSSIP_FIRST + (hash % GOSSIP_COUNT)), 6U, buffer,
            24U + sizeof(wrong_name) - 1U);

    static const char mismatched_name[] = "other/topic";
    memset(buffer, 0, sizeof(buffer));
    buffer[0]  = 8U;
    buffer[3]  = 0xFFU;
    le64(&buffer[8], hash);
    buffer[23] = (unsigned char)(sizeof(mismatched_name) - 1U);
    memcpy(&buffer[24], mismatched_name, sizeof(mismatched_name) - 1U);
    emit_16(canard, "bad_gossip_hash", true, (uint16_t)(GOSSIP_FIRST + (hash % GOSSIP_COUNT)), 7U, buffer,
            24U + sizeof(mismatched_name) - 1U);

    const unsigned char unrelated[] = { 1U, 2U, 3U, 4U };
    write_socketcan(false, 0x123U, sizeof(unrelated), unrelated);
    write_socketcan(false, UINT32_C(0x40000123), 0U, unrelated); // CAN_RTR_FLAG
    write_socketcan(false, UINT32_C(0x20000001), sizeof(unrelated), unrelated); // CAN_ERR_FLAG
}

int main(const int argc, char* const argv[])
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s VALID.pcap INVALID.pcap MANIFEST.tsv\n", argv[0]);
        return 2;
    }
    manifest = fopen(argv[3], "w");
    assert(manifest != NULL);

    const canard_mem_t memory = { .vtable = &memory_vtable, .context = NULL };
    const canard_mem_set_t memories = {
        .tx_transfer = memory, .tx_frame = memory, .rx_session = memory,
        .rx_payload = memory, .rx_filters = memory,
    };
    canard_t canard;
    assert(canard_new(&canard, &canard_vtable, memories, 1U, 4096U, UINT64_C(0x123456789ABCDEF0), 0U));
    assert(canard_set_node_id(&canard, 42U));

    pcap_open(argv[1]);
    generate_valid(&canard);
    pcap_close();
    pcap_open(argv[2]);
    generate_invalid(&canard);
    pcap_close();

    canard_destroy(&canard);
    assert(fclose(manifest) == 0);
    return 0;
}
