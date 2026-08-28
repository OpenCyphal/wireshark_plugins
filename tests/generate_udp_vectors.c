#include <udpard.h>

#define RAPIDHASH_COMPACT
#include <rapidhash.h>

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SUBJECT_ID_PINNED_MAX 8191U
#define SUBJECT_ID_MODULUS 8378431U
#define SUBJECT_ID_NORMAL_MAX (SUBJECT_ID_PINNED_MAX + SUBJECT_ID_MODULUS)
#define GOSSIP_FIRST (SUBJECT_ID_NORMAL_MAX + 1U)
#define BROADCAST_SUBJECT 0x7FFFFFU
#define GOSSIP_COUNT (BROADCAST_SUBJECT - GOSSIP_FIRST)
#define HEADER_SIZE 24U
#define UDP_HEADER_SIZE 32U
#define UDP_MTU 476U
#define MAX_DATAGRAMS 16U
#define MAX_DATAGRAM_SIZE 2048U

static const uint32_t source_ip   = UINT32_C(0xC000022A); // 192.0.2.42
static const uint16_t source_port = 13000U;

typedef struct
{
    size_t              size;
    unsigned char       data[MAX_DATAGRAM_SIZE];
    udpard_udpip_ep_t destination;
} captured_datagram_t;

typedef struct
{
    size_t              count;
    captured_datagram_t items[MAX_DATAGRAMS];
} capture_list_t;

static FILE*          capture;
static FILE*          manifest;
static uint32_t       packet_index;
static uint32_t       timestamp_us;
static capture_list_t datagrams;

static void put_u16_le(FILE* const out, const uint16_t value)
{
    fputc((int)(value & 0xFFU), out);
    fputc((int)(value >> 8U), out);
}

static void put_u32_le(FILE* const out, const uint32_t value)
{
    for (size_t i = 0; i < 4U; i++) fputc((int)((value >> (8U * i)) & 0xFFU), out);
}

static void put_u16_be_buf(unsigned char* const out, const uint16_t value)
{
    out[0] = (unsigned char)(value >> 8U);
    out[1] = (unsigned char)value;
}

static void put_u32_be_buf(unsigned char* const out, const uint32_t value)
{
    for (size_t i = 0; i < 4U; i++) out[i] = (unsigned char)(value >> (24U - (8U * i)));
}

static void put_u32_le_buf(unsigned char* const out, const uint32_t value)
{
    for (size_t i = 0; i < 4U; i++) out[i] = (unsigned char)(value >> (8U * i));
}

static uint32_t get_u32_le(const unsigned char* const in)
{
    return ((uint32_t)in[0]) | ((uint32_t)in[1] << 8U) | ((uint32_t)in[2] << 16U) | ((uint32_t)in[3] << 24U);
}

static void pcap_open(const char* const path)
{
    capture = fopen(path, "wb");
    assert(capture != NULL);
    packet_index = 0U;
    timestamp_us = 0U;
    put_u32_le(capture, UINT32_C(0xA1B2C3D4));
    put_u16_le(capture, 2U);
    put_u16_le(capture, 4U);
    put_u32_le(capture, 0U);
    put_u32_le(capture, 0U);
    put_u32_le(capture, 65535U);
    put_u32_le(capture, 1U); // LINKTYPE_ETHERNET
}

static void pcap_close(void)
{
    assert(fclose(capture) == 0);
    capture = NULL;
}

static uint16_t ipv4_checksum(const unsigned char* const header)
{
    uint32_t sum = 0U;
    for (size_t i = 0; i < 20U; i += 2U) sum += ((uint32_t)header[i] << 8U) | header[i + 1U];
    while ((sum >> 16U) != 0U) sum = (sum & 0xFFFFU) + (sum >> 16U);
    return (uint16_t)~sum;
}

static void write_udp(const uint32_t       destination_ip,
                      const uint16_t       destination_port,
                      const size_t         payload_size,
                      const unsigned char* payload)
{
    assert(payload_size <= MAX_DATAGRAM_SIZE);
    unsigned char packet[14U + 20U + 8U + MAX_DATAGRAM_SIZE] = { 0 };
    static const unsigned char destination_mac[6] = { 0x01U, 0x00U, 0x5EU, 0x00U, 0x00U, 0x01U };
    static const unsigned char source_mac[6]      = { 0x02U, 0x00U, 0x00U, 0x00U, 0x00U, 0x2AU };
    memcpy(&packet[0], destination_mac, sizeof(destination_mac));
    memcpy(&packet[6], source_mac, sizeof(source_mac));
    packet[12] = 0x08U;
    packet[13] = 0x00U;
    unsigned char* const ip = &packet[14];
    ip[0]                   = 0x45U;
    put_u16_be_buf(&ip[2], (uint16_t)(20U + 8U + payload_size));
    put_u16_be_buf(&ip[4], (uint16_t)packet_index);
    ip[8] = 64U;
    ip[9] = 17U;
    put_u32_be_buf(&ip[12], source_ip);
    put_u32_be_buf(&ip[16], destination_ip);
    put_u16_be_buf(&ip[10], ipv4_checksum(ip));
    unsigned char* const udp = &packet[34];
    put_u16_be_buf(&udp[0], source_port);
    put_u16_be_buf(&udp[2], destination_port);
    put_u16_be_buf(&udp[4], (uint16_t)(8U + payload_size));
    memcpy(&udp[8], payload, payload_size);
    const uint32_t packet_size = (uint32_t)(42U + payload_size);
    put_u32_le(capture, 1U);
    put_u32_le(capture, timestamp_us);
    put_u32_le(capture, packet_size);
    put_u32_le(capture, packet_size);
    assert(fwrite(packet, packet_size, 1U, capture) == 1U);
    packet_index++;
    timestamp_us += 1000U;
}

static void* mem_alloc(void* const context, const size_t size)
{
    (void)context;
    return malloc(size);
}

static void mem_free(void* const context, const size_t size, void* const pointer)
{
    (void)context;
    (void)size;
    free(pointer);
}

static bool capture_eject(udpard_tx_t* const tx, udpard_tx_ejection_t* const ejection)
{
    capture_list_t* const out = tx->user;
    assert(out != NULL);
    assert(out->count < MAX_DATAGRAMS);
    captured_datagram_t* const item = &out->items[out->count++];
    assert(ejection->datagram.size <= sizeof(item->data));
    item->size        = ejection->datagram.size;
    item->destination = ejection->destination;
    memcpy(item->data, ejection->datagram.data, item->size);
    return true;
}

static const udpard_tx_vtable_t tx_vtable = { .eject = capture_eject };
static const udpard_mem_vtable_t mem_vtable = { .base = { .free = mem_free }, .alloc = mem_alloc };

static void le32(unsigned char* const out, const uint32_t value) { put_u32_le_buf(out, value); }

static void le48(unsigned char* const out, const uint64_t value)
{
    for (size_t i = 0; i < 6U; i++) out[i] = (unsigned char)(value >> (8U * i));
}

static void le64(unsigned char* const out, const uint64_t value)
{
    for (size_t i = 0; i < 8U; i++) out[i] = (unsigned char)(value >> (8U * i));
}

static uint32_t subject_id_23(const uint64_t hash, const uint32_t evictions)
{
    if (evictions >= UINT32_C(0xFFFFE000)) return UINT32_MAX - evictions;
    const uint64_t h = hash % SUBJECT_ID_MODULUS;
    const uint64_t e = evictions % SUBJECT_ID_MODULUS;
    return SUBJECT_ID_PINNED_MAX + 1U + (uint32_t)((h + ((e * e) % SUBJECT_ID_MODULUS)) % SUBJECT_ID_MODULUS);
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

static udpard_bytes_scattered_t payload(const void* const data, const size_t size)
{
    return (udpard_bytes_scattered_t){ .bytes = { .size = size, .data = data }, .next = NULL };
}

static void poll_tx(udpard_tx_t* const tx)
{
    while (udpard_tx_pending_ifaces(tx) != 0U) udpard_tx_poll(tx, 1, UDPARD_IFACE_BITMAP_ALL);
}

static void flush_datagram(const size_t index)
{
    assert(index < datagrams.count);
    const captured_datagram_t* const item = &datagrams.items[index];
    write_udp(item->destination.ip, item->destination.port, item->size, item->data);
}

static void flush_datagram_to(const size_t index, const uint32_t destination_ip, const uint16_t destination_port)
{
    assert(index < datagrams.count);
    const captured_datagram_t* const item = &datagrams.items[index];
    write_udp(destination_ip, destination_port, item->size, item->data);
}

static void flush_in_order(const char* const name)
{
    for (size_t i = 0; i < datagrams.count; i++) flush_datagram(i);
    fprintf(manifest, "%s\t%u\n", name, packet_index);
    datagrams.count = 0U;
}

static void push_subject(udpard_tx_t* const tx,
                         const char* const name,
                         const uint32_t subject,
                         const uint64_t transfer_id,
                         const void* const data,
                         const size_t size)
{
    assert(udpard_tx_push(tx, 0, 1000000, 1U, udpard_prio_nominal, transfer_id,
                          udpard_make_subject_endpoint(subject), payload(data, size), NULL));
    poll_tx(tx);
    flush_in_order(name);
}

static void push_unicast(udpard_tx_t* const tx, const char* const name, const void* const data, const size_t size)
{
    udpard_udpip_ep_t endpoints[UDPARD_IFACE_COUNT_MAX] = { 0 };
    endpoints[0] = (udpard_udpip_ep_t){ .ip = UINT32_C(0xC0000214), .port = 12000U }; // 192.0.2.20
    assert(udpard_tx_push_unicast(tx, 0, 1000000, udpard_prio_high, endpoints, payload(data, size), NULL));
    poll_tx(tx);
    flush_in_order(name);
}

static uint32_t crc32c(const size_t size, const unsigned char* const data)
{
    uint32_t crc = UINT32_MAX;
    for (size_t i = 0; i < size; i++) {
        crc ^= data[i];
        for (size_t bit = 0; bit < 8U; bit++) crc = ((crc & 1U) != 0U) ? ((crc >> 1U) ^ UINT32_C(0x82F63B78)) : (crc >> 1U);
    }
    return crc ^ UINT32_MAX;
}

static void repair_header_crc(unsigned char* const datagram)
{
    put_u32_le_buf(&datagram[28], crc32c(28U, datagram));
}

static captured_datagram_t rewrite_fragment(const captured_datagram_t* const base,
                                            const uint32_t offset,
                                            const size_t total_size,
                                            const size_t fragment_size,
                                            const unsigned char* const full_payload)
{
    assert((offset + fragment_size) <= total_size);
    assert((UDP_HEADER_SIZE + fragment_size) <= MAX_DATAGRAM_SIZE);
    captured_datagram_t out = *base;
    out.size = UDP_HEADER_SIZE + fragment_size;
    put_u32_le_buf(&out.data[16], offset);
    put_u32_le_buf(&out.data[20], (uint32_t)total_size);
    put_u32_le_buf(&out.data[24], crc32c(offset + fragment_size, full_payload));
    memcpy(&out.data[UDP_HEADER_SIZE], &full_payload[offset], fragment_size);
    repair_header_crc(out.data);
    return out;
}

static void generate_valid(udpard_tx_t* const tx)
{
    static const char topic[] = "plant/temperature";
    const uint64_t hash = rapidhash(topic, sizeof(topic) - 1U);
    const uint32_t sid  = subject_id_23(hash, 0U);
    unsigned char buffer[1400];

    make_message_header(buffer, 0U, -1, 0U, hash, UINT64_C(0x1122334455667788));
    memcpy(&buffer[24], "udp", 3U);
    push_subject(tx, "udp_msg_be_single", sid, UINT64_C(0x010203040501), buffer, 27U);

    make_message_header(buffer, 1U, 4, 0U, hash, UINT64_C(0x8877665544332211));
    for (size_t i = 24U; i < 1124U; i++) buffer[i] = (unsigned char)i;
    assert(udpard_tx_push(tx, 0, 1000000, 1U, udpard_prio_nominal, UINT64_C(0x010203040502),
                          udpard_make_subject_endpoint(sid), payload(buffer, 1124U), NULL));
    poll_tx(tx);
    assert(datagrams.count == 3U);
    flush_datagram(2U); // EOT first.
    flush_datagram(0U); // SOT second.
    flush_datagram(1U); // The middle frame completes the transfer.
    flush_datagram(0U); // A redundant-interface duplicate after completion.
    fprintf(manifest, "udp_msg_rel_reordered\t%u\n", packet_index);
    datagrams.count = 0U;

    make_ack_header(buffer, 2U, hash, UINT64_C(0x8877665544332211));
    push_unicast(tx, "udp_msg_ack", buffer, 24U);
    buffer[0] = 3U;
    push_unicast(tx, "udp_msg_nack", buffer, 24U);
    for (uint8_t type = 4U; type <= 7U; type++) {
        make_response_header(buffer, type, (uint8_t)(0xA0U + type), UINT64_C(0x010203040506), hash,
                             UINT64_C(0x1122334455667788));
        size_t size = 24U;
        if (type <= 5U) {
            memcpy(&buffer[24], "response", 8U);
            size += 8U;
        }
        static const char* const names[] = { "udp_rsp_be", "udp_rsp_rel", "udp_rsp_ack", "udp_rsp_nack" };
        push_unicast(tx, names[type - 4U], buffer, size);
    }

    memset(buffer, 0, sizeof(buffer));
    buffer[0] = 8U;
    buffer[3] = 2U;
    le64(&buffer[8], hash);
    buffer[23] = (unsigned char)(sizeof(topic) - 1U);
    memcpy(&buffer[24], topic, sizeof(topic) - 1U);
    push_subject(tx, "udp_gossip_broadcast", BROADCAST_SUBJECT, UINT64_C(0x010203040510),
                 buffer, 24U + sizeof(topic) - 1U);
    push_subject(tx, "udp_gossip_shard", GOSSIP_FIRST + (uint32_t)(hash % GOSSIP_COUNT), UINT64_C(0x010203040511),
                 buffer, 24U + sizeof(topic) - 1U);

    static const char pattern[] = "plant/*";
    memset(buffer, 0, sizeof(buffer));
    buffer[0] = 9U;
    buffer[23] = (unsigned char)(sizeof(pattern) - 1U);
    memcpy(&buffer[24], pattern, sizeof(pattern) - 1U);
    push_subject(tx, "udp_scout", BROADCAST_SUBJECT, UINT64_C(0x010203040512),
                 buffer, 24U + sizeof(pattern) - 1U);

    // A unicast transfer is one session across redundant local interfaces even
    // when the destination IP endpoints differ.
    make_message_header(buffer, 1U, 3, 0U, hash, UINT64_C(0xABCDEF0123456789));
    for (size_t i = 24U; i < 1100U; i++) buffer[i] = (unsigned char)(0x20U + i);
    udpard_udpip_ep_t endpoints[UDPARD_IFACE_COUNT_MAX] = { 0 };
    endpoints[0] = (udpard_udpip_ep_t){ .ip = UINT32_C(0xC0000214), .port = 12000U };
    assert(udpard_tx_push_unicast(tx, 0, 1000000, udpard_prio_high, endpoints, payload(buffer, 1100U), NULL));
    poll_tx(tx);
    assert(datagrams.count == 3U);
    flush_datagram_to(0U, UINT32_C(0xC0000214), 12000U);
    flush_datagram_to(1U, UINT32_C(0xC0000215), 12001U);
    flush_datagram_to(2U, UINT32_C(0xC0000216), 12002U);
    fprintf(manifest, "udp_unicast_redundant_endpoints\t%u\n", packet_index);
    datagrams.count = 0U;

    // Re-segment a reference transfer with a variable MTU and a 76-byte
    // identical overlap, then deliver it out of order.
    make_message_header(buffer, 1U, 5, 0U, hash, UINT64_C(0xABCDEF0123456790));
    for (size_t i = 24U; i < 1024U; i++) buffer[i] = (unsigned char)(0x40U + i);
    assert(udpard_tx_push(tx, 0, 1000000, 1U, udpard_prio_nominal, UINT64_C(0x010203040513),
                          udpard_make_subject_endpoint(sid), payload(buffer, 1024U), NULL));
    poll_tx(tx);
    assert(datagrams.count == 3U);
    const captured_datagram_t overlap_first = rewrite_fragment(&datagrams.items[0], 0U, 1024U, 476U, buffer);
    const captured_datagram_t overlap_middle = rewrite_fragment(&datagrams.items[1], 400U, 1024U, 476U, buffer);
    const captured_datagram_t overlap_last = rewrite_fragment(&datagrams.items[2], 876U, 1024U, 148U, buffer);
    write_udp(overlap_last.destination.ip, overlap_last.destination.port, overlap_last.size, overlap_last.data);
    write_udp(overlap_first.destination.ip, overlap_first.destination.port, overlap_first.size, overlap_first.data);
    write_udp(overlap_middle.destination.ip, overlap_middle.destination.port, overlap_middle.size, overlap_middle.data);
    fprintf(manifest, "udp_overlap_variable_mtu\t%u\n", packet_index);
    datagrams.count = 0U;

    // A contained EOT duplicate must not replace the CRC selected by the first
    // accepted EOT frame.
    make_message_header(buffer, 1U, 6, 0U, hash, UINT64_C(0xABCDEF0123456791));
    for (size_t i = 24U; i < 1024U; i++) buffer[i] = (unsigned char)(0x60U + i);
    assert(udpard_tx_push(tx, 0, 1000000, 1U, udpard_prio_nominal, UINT64_C(0x010203040514),
                          udpard_make_subject_endpoint(sid), payload(buffer, 1024U), NULL));
    poll_tx(tx);
    assert(datagrams.count == 3U);
    flush_datagram(2U);
    captured_datagram_t duplicate_eot = datagrams.items[2];
    duplicate_eot.data[24] ^= 1U;
    repair_header_crc(duplicate_eot.data);
    write_udp(duplicate_eot.destination.ip, duplicate_eot.destination.port, duplicate_eot.size, duplicate_eot.data);
    flush_datagram(0U);
    flush_datagram(1U);
    fprintf(manifest, "udp_duplicate_eot_crc\t%u\n", packet_index);
    datagrams.count = 0U;
}

static void write_modified(const captured_datagram_t* const base, const char* const name,
                           void (*const modify)(unsigned char*, size_t))
{
    captured_datagram_t item = *base;
    modify(item.data, item.size);
    write_udp(item.destination.ip, item.destination.port, item.size, item.data);
    fprintf(manifest, "%s\t%u\n", name, packet_index);
}

static void modify_bad_header_crc(unsigned char* const data, const size_t size)
{
    (void)size;
    data[28] ^= 1U;
}

static void modify_version(unsigned char* const data, const size_t size)
{
    (void)size;
    data[0] = (unsigned char)((data[0] & 0xE0U) | 3U);
    repair_header_crc(data);
}

static void modify_incompat(unsigned char* const data, const size_t size)
{
    (void)size;
    data[1] |= 0x20U;
    repair_header_crc(data);
}

static void modify_void(unsigned char* const data, const size_t size)
{
    (void)size;
    data[1] |= 1U;
    repair_header_crc(data);
}

static void modify_overflow(unsigned char* const data, const size_t size)
{
    put_u32_le_buf(&data[16], get_u32_le(&data[20]));
    (void)size;
    repair_header_crc(data);
}

static void modify_bad_prefix(unsigned char* const data, const size_t size)
{
    (void)size;
    data[24] ^= 1U;
    repair_header_crc(data);
}

static void generate_invalid(udpard_tx_t* const tx)
{
    static const char topic[] = "bad/topic";
    const uint64_t hash = rapidhash(topic, sizeof(topic) - 1U);
    const uint32_t sid  = subject_id_23(hash, 0U);
    unsigned char buffer[1200];
    make_message_header(buffer, 0U, -1, 0U, hash, 1U);
    memcpy(&buffer[24], "bad", 3U);
    assert(udpard_tx_push(tx, 0, 1000000, 1U, udpard_prio_nominal, 100U,
                          udpard_make_subject_endpoint(sid), payload(buffer, 27U), NULL));
    poll_tx(tx);
    assert(datagrams.count == 1U);
    write_udp(datagrams.items[0].destination.ip, datagrams.items[0].destination.port, 10U, datagrams.items[0].data);
    fprintf(manifest, "udp_short\t%u\n", packet_index);
    write_modified(&datagrams.items[0], "udp_bad_header_crc", modify_bad_header_crc);
    write_modified(&datagrams.items[0], "udp_bad_version", modify_version);
    write_modified(&datagrams.items[0], "udp_incompat", modify_incompat);
    write_modified(&datagrams.items[0], "udp_void", modify_void);
    write_modified(&datagrams.items[0], "udp_offset_overflow", modify_overflow);
    write_modified(&datagrams.items[0], "udp_bad_first_prefix", modify_bad_prefix);
    datagrams.count = 0U;

    make_message_header(buffer, 1U, 1, 0U, hash, 2U);
    for (size_t i = 24U; i < 1024U; i++) buffer[i] = (unsigned char)(0x80U + i);
    assert(udpard_tx_push(tx, 0, 1000000, 1U, udpard_prio_nominal, 101U,
                          udpard_make_subject_endpoint(sid), payload(buffer, 1024U), NULL));
    poll_tx(tx);
    assert(datagrams.count == 3U);
    for (size_t i = 0; i < datagrams.count; i++) {
        captured_datagram_t item = datagrams.items[i];
        const uint32_t offset = get_u32_le(&item.data[16]);
        const uint32_t total  = get_u32_le(&item.data[20]);
        if (offset + item.size - UDP_HEADER_SIZE == total) {
            item.data[24] ^= 1U;
            repair_header_crc(item.data);
        }
        write_udp(item.destination.ip, item.destination.port, item.size, item.data);
    }
    fprintf(manifest, "udp_bad_transfer_crc\t%u\n", packet_index);
    datagrams.count = 0U;

    const unsigned char unrelated[] = { 2U, 0U, 1U, 2U, 3U, 4U };
    write_udp(UINT32_C(0xC0000214), 9999U, sizeof(unrelated), unrelated);
    fprintf(manifest, "udp_unrelated\t%u\n", packet_index);
}

int main(const int argc, char* const argv[])
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s VALID.pcap INVALID.pcap MANIFEST.tsv\n", argv[0]);
        return 2;
    }
    manifest = fopen(argv[3], "a");
    assert(manifest != NULL);
    const udpard_mem_t memory = { .vtable = &mem_vtable, .context = NULL };
    udpard_tx_mem_resources_t resources = { .transfer = memory };
    for (size_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) resources.payload[i] = memory;
    udpard_tx_t tx;
    assert(udpard_tx_new(&tx, UINT64_C(0x1122334455667788), UINT64_C(0x010203040500),
                         64U, 1U, resources, &tx_vtable));
    tx.mtu[0] = UDP_MTU;
    tx.user   = &datagrams;

    pcap_open(argv[1]);
    generate_valid(&tx);
    pcap_close();
    pcap_open(argv[2]);
    generate_invalid(&tx);
    pcap_close();

    udpard_tx_free(&tx);
    assert(fclose(manifest) == 0);
    return 0;
}
