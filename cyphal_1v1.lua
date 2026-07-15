-- Cyphal v1.1 session dissector with Cyphal/CAN and Cyphal/UDP transports.

set_plugin_info({
    version = "1.1.0",
    author = "OpenCyphal contributors",
    description = "Cyphal v1.1 session dissector for Cyphal/CAN and Cyphal/UDP",
})

local SESSION_HEADER_SIZE = 24
local TOPIC_NAME_MAX = 200
local SUBJECT_ID_PINNED_MAX = 8191
local CAN_SUBJECT_ID_MODULUS = 57203
local CAN_SUBJECT_ID_NORMAL_MAX = SUBJECT_ID_PINNED_MAX + CAN_SUBJECT_ID_MODULUS -- 65394
local CAN_SUBJECT_ID_GOSSIP_FIRST = CAN_SUBJECT_ID_NORMAL_MAX + 1                -- 65395
local CAN_SUBJECT_ID_GOSSIP_COUNT = 140
local CAN_SUBJECT_ID_BROADCAST = 65535
local UDP_SUBJECT_ID_MODULUS = 8378431
local UDP_SUBJECT_ID_NORMAL_MAX = SUBJECT_ID_PINNED_MAX + UDP_SUBJECT_ID_MODULUS -- 8386622
local UDP_SUBJECT_ID_GOSSIP_FIRST = UDP_SUBJECT_ID_NORMAL_MAX + 1                -- 8386623
local UDP_SUBJECT_ID_BROADCAST = 0x7FFFFF
local UDP_SUBJECT_ID_GOSSIP_COUNT = UDP_SUBJECT_ID_BROADCAST - UDP_SUBJECT_ID_GOSSIP_FIRST -- 1984
local UDP_HEADER_SIZE = 32
local UDP_HEADER_VERSION = 2
local UDP_PORT = 9382
local EVICTIONS_PINNED_MIN = 0xFFFFE000
local UNICAST_SERVICE_ID = 511
local REASSEMBLY_TIMEOUT_SECONDS = 30

local priority_names = {
    [0] = "Exceptional", [1] = "Immediate", [2] = "Fast", [3] = "High",
    [4] = "Nominal", [5] = "Low", [6] = "Slow", [7] = "Optional",
}

local session_color_names = {
    [1] = "Pink 1", [2] = "Pink 2", [3] = "Purple 1", [4] = "Purple 2",
    [5] = "Green 1", [6] = "Green 2", [7] = "Green 3", [8] = "Yellow 1",
    [9] = "Yellow 2", [10] = "Gray",
}

local session_type_names = {
    [0] = "Best-effort message",
    [1] = "Reliable message",
    [2] = "Message ACK",
    [3] = "Message NACK",
    [4] = "Best-effort response",
    [5] = "Reliable response",
    [6] = "Response ACK",
    [7] = "Response NACK",
    [8] = "Gossip",
    [9] = "Scout",
}

local cyphal_can = Proto("cyphalcan11", "Cyphal/CAN v1")
local cyphal_udp = Proto("cyphaludp11", "Cyphal/UDP v1.1")
local cyphal_session = Proto("cyphal11", "Cyphal v1.1 Session")

local f_can_id = ProtoField.uint32("cyphalcan11.can_id", "Extended CAN ID", base.HEX)
local f_session_color = ProtoField.uint8(
    "cyphalcan11.session_color", "Session color", base.DEC, session_color_names)
local f_version = ProtoField.string("cyphalcan11.version", "Protocol version")
local f_kind = ProtoField.string("cyphalcan11.kind", "Transfer kind")
local f_can_fd = ProtoField.bool("cyphalcan11.can_fd", "CAN FD frame")
local f_priority = ProtoField.uint8("cyphalcan11.priority", "Priority", base.DEC, priority_names)
local f_service = ProtoField.bool("cyphalcan11.service", "Service transfer")
local f_request = ProtoField.bool("cyphalcan11.request", "Request")
local f_reserved = ProtoField.uint8("cyphalcan11.reserved", "Reserved bits", base.HEX)
local f_v10_fixed = ProtoField.uint8("cyphalcan11.v10_fixed", "v1.0 fixed bits", base.BIN)
local f_subject_id = ProtoField.uint16("cyphalcan11.subject_id", "Subject-ID", base.DEC_HEX)
local f_service_id = ProtoField.uint16("cyphalcan11.service_id", "Service-ID", base.DEC)
local f_source = ProtoField.uint8("cyphalcan11.source_node_id", "Source node-ID", base.DEC)
local f_destination = ProtoField.uint8("cyphalcan11.destination_node_id", "Destination node-ID", base.DEC)
local f_anonymous = ProtoField.bool("cyphalcan11.anonymous", "Anonymous transfer")
local f_discriminator = ProtoField.uint8("cyphalcan11.anonymous_discriminator", "Anonymous discriminator", base.HEX)
local f_frame_payload = ProtoField.bytes("cyphalcan11.frame_payload", "Frame payload")
local f_tail = ProtoField.uint8("cyphalcan11.tail", "Tail byte", base.HEX)
local f_sot = ProtoField.bool("cyphalcan11.sot", "Start of transfer", 8, nil, 0x80)
local f_eot = ProtoField.bool("cyphalcan11.eot", "End of transfer", 8, nil, 0x40)
local f_toggle = ProtoField.bool("cyphalcan11.toggle", "Toggle", 8, nil, 0x20)
local f_transfer_id = ProtoField.uint8("cyphalcan11.transfer_id", "Transfer-ID", base.DEC, nil, 0x1F)
local f_fragment_index = ProtoField.uint32("cyphalcan11.fragment_index", "Fragment index", base.DEC)
local f_fragment_count = ProtoField.uint32("cyphalcan11.fragment_count", "Fragment count", base.DEC)
local f_reassembled_length = ProtoField.uint32("cyphalcan11.reassembled_length", "Reassembled length", base.DEC)
local f_reassembled_in = ProtoField.framenum("cyphalcan11.reassembled_in", "Reassembled in")
local f_crc = ProtoField.uint16("cyphalcan11.crc", "Transfer CRC", base.HEX)
local f_crc_calculated = ProtoField.uint16("cyphalcan11.crc_calculated", "Calculated transfer CRC", base.HEX)
local f_crc_good = ProtoField.bool("cyphalcan11.crc_good", "Transfer CRC good")
local f_payload = ProtoField.bytes("cyphalcan11.payload", "Opaque transfer payload")

cyphal_can.fields = {
    f_can_id, f_session_color, f_version, f_kind, f_can_fd, f_priority, f_service, f_request, f_reserved, f_v10_fixed,
    f_subject_id, f_service_id, f_source, f_destination, f_anonymous, f_discriminator,
    f_frame_payload, f_tail, f_sot, f_eot, f_toggle, f_transfer_id, f_fragment_index,
    f_fragment_count, f_reassembled_length, f_reassembled_in, f_crc, f_crc_calculated,
    f_crc_good, f_payload,
}

local uf = {}
uf.version = ProtoField.uint8("cyphaludp11.version", "Header version", base.DEC, nil, 0x1F)
uf.priority = ProtoField.uint8("cyphaludp11.priority", "Priority", base.DEC, priority_names, 0xE0)
uf.void = ProtoField.uint8("cyphaludp11.void", "Void", base.HEX, nil, 0x1F)
uf.incompatibility = ProtoField.uint8("cyphaludp11.incompatibility", "Incompatibility", base.HEX, nil, 0xE0)
uf.transfer_id = ProtoField.uint64("cyphaludp11.transfer_id", "Transfer-ID", base.DEC)
uf.sender_uid = ProtoField.uint64("cyphaludp11.sender_uid", "Sender UID", base.HEX)
uf.frame_offset = ProtoField.uint32("cyphaludp11.frame_payload_offset", "Frame payload offset", base.DEC)
uf.transfer_size = ProtoField.uint32("cyphaludp11.transfer_payload_size", "Transfer payload size", base.DEC)
uf.prefix_crc = ProtoField.uint32("cyphaludp11.prefix_crc32c", "Payload prefix CRC-32C", base.HEX)
uf.prefix_crc_calculated = ProtoField.uint32(
    "cyphaludp11.prefix_crc32c_calculated", "Calculated payload prefix CRC-32C", base.HEX)
uf.prefix_crc_good = ProtoField.bool("cyphaludp11.prefix_crc32c_good", "Payload prefix CRC-32C good")
uf.header_crc = ProtoField.uint32("cyphaludp11.header_crc32c", "Header CRC-32C", base.HEX)
uf.header_crc_calculated = ProtoField.uint32(
    "cyphaludp11.header_crc32c_calculated", "Calculated header CRC-32C", base.HEX)
uf.header_crc_good = ProtoField.bool("cyphaludp11.header_crc32c_good", "Header CRC-32C good")
uf.subject_id = ProtoField.uint32("cyphaludp11.subject_id", "Subject-ID", base.DEC_HEX)
uf.scope = ProtoField.string("cyphaludp11.scope", "Delivery scope")
uf.source_endpoint = ProtoField.string("cyphaludp11.source_endpoint", "Source endpoint")
uf.destination_endpoint = ProtoField.string("cyphaludp11.destination_endpoint", "Destination endpoint")
uf.logical_source = ProtoField.string("cyphaludp11.logical_source", "Logical source")
uf.logical_destination = ProtoField.string("cyphaludp11.logical_destination", "Logical destination")
uf.sot = ProtoField.bool("cyphaludp11.sot", "Start of transfer")
uf.eot = ProtoField.bool("cyphaludp11.eot", "End of transfer")
uf.duplicate = ProtoField.bool("cyphaludp11.duplicate", "Duplicate frame")
uf.session_color = ProtoField.uint8(
    "cyphaludp11.session_color", "Session color", base.DEC, session_color_names)
uf.frame_payload = ProtoField.bytes("cyphaludp11.frame_payload", "Frame payload")
uf.fragment_count = ProtoField.uint32("cyphaludp11.fragment_count", "Fragment count", base.DEC)
uf.reassembled_length = ProtoField.uint32("cyphaludp11.reassembled_length", "Reassembled length", base.DEC)
uf.reassembled_in = ProtoField.framenum("cyphaludp11.reassembled_in", "Reassembled in")
uf.payload = ProtoField.bytes("cyphaludp11.payload", "Opaque transfer payload")

cyphal_udp.fields = {
    uf.version, uf.priority, uf.void, uf.incompatibility, uf.transfer_id, uf.sender_uid,
    uf.frame_offset, uf.transfer_size, uf.prefix_crc, uf.prefix_crc_calculated, uf.prefix_crc_good,
    uf.header_crc, uf.header_crc_calculated, uf.header_crc_good, uf.subject_id, uf.scope,
    uf.source_endpoint, uf.destination_endpoint, uf.logical_source, uf.logical_destination,
    uf.sot, uf.eot, uf.duplicate, uf.session_color,
    uf.frame_payload, uf.fragment_count, uf.reassembled_length, uf.reassembled_in, uf.payload,
}

local sf_type = ProtoField.uint8("cyphal11.type", "Session type", base.DEC, session_type_names)
local sf_scope = ProtoField.string("cyphal11.scope", "Delivery scope")
local sf_void = ProtoField.bytes("cyphal11.void", "Void")
local sf_incompat8 = ProtoField.uint8("cyphal11.incompatibility8", "Incompatibility", base.HEX)
local sf_incompat32 = ProtoField.uint32("cyphal11.incompatibility32", "Incompatibility", base.HEX)
local sf_incompat64 = ProtoField.uint64("cyphal11.incompatibility64", "Incompatibility", base.HEX)
local sf_lage = ProtoField.int8("cyphal11.lage", "Log-age", base.DEC)
local sf_evictions = ProtoField.uint32("cyphal11.evictions", "Evictions", base.DEC)
local sf_topic_hash = ProtoField.uint64("cyphal11.topic_hash", "Topic hash", base.HEX)
local sf_message_tag = ProtoField.uint64("cyphal11.message_tag", "Message tag", base.HEX)
local sf_response_tag = ProtoField.uint8("cyphal11.response_tag", "Response correlation tag", base.HEX)
local sf_response_seqno = ProtoField.uint64("cyphal11.response_seqno", "Response sequence number", base.DEC)
local sf_name_length = ProtoField.uint8("cyphal11.name_length", "Name/pattern length", base.DEC)
local sf_topic_name = ProtoField.string("cyphal11.topic_name", "Topic name")
local sf_resolved_topic_name = ProtoField.string("cyphal11.resolved_topic_name", "Resolved topic name")
local sf_pattern = ProtoField.string("cyphal11.pattern", "Scout pattern")
local sf_expected_subject = ProtoField.uint32("cyphal11.expected_subject_id", "Calculated subject-ID", base.DEC_HEX)
local sf_expected_gossip = ProtoField.uint32("cyphal11.expected_gossip_subject_id", "Calculated gossip subject-ID", base.DEC_HEX)
local sf_pinned = ProtoField.bool("cyphal11.pinned", "Pinned topic")
local sf_name_hash_good = ProtoField.bool("cyphal11.name_hash_good", "Topic name hash good")
local sf_application_payload = ProtoField.bytes("cyphal11.application_payload", "Application payload")
local sf_padding = ProtoField.bytes("cyphal11.padding", "Transport padding")
local sf_trailing = ProtoField.bytes("cyphal11.trailing_data", "Trailing data")
local sf_raw_body = ProtoField.bytes("cyphal11.raw_body", "Undecoded session body")

cyphal_session.fields = {
    sf_type, sf_scope, sf_void, sf_incompat8, sf_incompat32, sf_incompat64, sf_lage,
    sf_evictions, sf_topic_hash, sf_message_tag, sf_response_tag, sf_response_seqno,
    sf_name_length, sf_topic_name, sf_resolved_topic_name, sf_pattern, sf_expected_subject, sf_expected_gossip,
    sf_pinned, sf_name_hash_good, sf_application_payload, sf_padding, sf_trailing, sf_raw_body,
}

local ex_can_malformed = ProtoExpert.new(
    "cyphalcan11.expert.malformed", "Malformed Cyphal/CAN frame", expert.group.MALFORMED, expert.severity.ERROR)
local ex_can_sequence = ProtoExpert.new(
    "cyphalcan11.expert.sequence", "Invalid transfer sequence", expert.group.SEQUENCE, expert.severity.ERROR)
local ex_can_crc = ProtoExpert.new(
    "cyphalcan11.expert.crc", "Bad transfer CRC", expert.group.CHECKSUM, expert.severity.ERROR)
local ex_can_noncanonical = ProtoExpert.new(
    "cyphalcan11.expert.noncanonical", "Non-canonical Cyphal/CAN identifier", expert.group.PROTOCOL, expert.severity.WARN)
local ex_can_reassembly = ProtoExpert.new(
    "cyphalcan11.expert.reassembly", "Transfer reassembly failed", expert.group.REASSEMBLE, expert.severity.ERROR)

cyphal_can.experts = { ex_can_malformed, ex_can_sequence, ex_can_crc, ex_can_noncanonical, ex_can_reassembly }

local udp_ex = {}
udp_ex.malformed = ProtoExpert.new(
    "cyphaludp11.expert.malformed", "Malformed Cyphal/UDP frame", expert.group.MALFORMED, expert.severity.ERROR)
udp_ex.header_crc = ProtoExpert.new(
    "cyphaludp11.expert.header_crc", "Bad Cyphal/UDP header CRC", expert.group.CHECKSUM, expert.severity.ERROR)
udp_ex.prefix_crc = ProtoExpert.new(
    "cyphaludp11.expert.prefix_crc", "Bad Cyphal/UDP payload CRC", expert.group.CHECKSUM, expert.severity.ERROR)
udp_ex.incompatible = ProtoExpert.new(
    "cyphaludp11.expert.incompatible", "Unsupported Cyphal/UDP header", expert.group.PROTOCOL, expert.severity.ERROR)
udp_ex.noncanonical = ProtoExpert.new(
    "cyphaludp11.expert.noncanonical", "Non-canonical Cyphal/UDP header", expert.group.PROTOCOL, expert.severity.WARN)
udp_ex.reassembly = ProtoExpert.new(
    "cyphaludp11.expert.reassembly", "Cyphal/UDP reassembly failed", expert.group.REASSEMBLE, expert.severity.ERROR)

cyphal_udp.experts = {
    udp_ex.malformed, udp_ex.header_crc, udp_ex.prefix_crc, udp_ex.incompatible,
    udp_ex.noncanonical, udp_ex.reassembly,
}

local ex_session_malformed = ProtoExpert.new(
    "cyphal11.expert.malformed", "Malformed session header", expert.group.MALFORMED, expert.severity.ERROR)
local ex_session_incompatible = ProtoExpert.new(
    "cyphal11.expert.incompatible", "Unsupported incompatible session data", expert.group.PROTOCOL, expert.severity.ERROR)
local ex_session_scope = ProtoExpert.new(
    "cyphal11.expert.scope", "Invalid delivery scope", expert.group.PROTOCOL, expert.severity.ERROR)
local ex_session_mismatch = ProtoExpert.new(
    "cyphal11.expert.mismatch", "Inconsistent session metadata", expert.group.PROTOCOL, expert.severity.WARN)
local ex_session_unsupported = ProtoExpert.new(
    "cyphal11.expert.unsupported", "Unsupported session type", expert.group.UNDECODED, expert.severity.WARN)

cyphal_session.experts = {
    ex_session_malformed, ex_session_incompatible, ex_session_scope, ex_session_mismatch, ex_session_unsupported,
}

cyphal_can.prefs.max_reassembly_bytes = Pref.uint(
    "Maximum reassembled transfer size", 16 * 1024 * 1024,
    "Abort a malformed or hostile transfer when its buffered payload exceeds this many bytes")
cyphal_udp.prefs.max_reassembly_bytes = Pref.uint(
    "Maximum reassembled transfer size", 16 * 1024 * 1024,
    "Abort a malformed or hostile transfer when its advertised payload exceeds this many bytes")
cyphal_udp.prefs.max_buffered_bytes = Pref.uint(
    "Maximum total UDP reassembly memory", 64 * 1024 * 1024,
    "Abort a transfer rather than retaining more fragment payload bytes across all active UDP transfers")
cyphal_udp.prefs.max_active_transfers = Pref.uint(
    "Maximum active UDP transfers", 1024,
    "Reject new incomplete transfers once this many UDP transfers are being reassembled")
cyphal_udp.prefs.max_fragments = Pref.uint(
    "Maximum UDP fragments per transfer", 65536,
    "Abort a transfer that requires more datagrams than this limit")
cyphal_udp.prefs.max_cached_payload_bytes = Pref.uint(
    "Maximum completed UDP payload cache", 64 * 1024 * 1024,
    "Retain at most this many reassembled payload bytes for packet-detail redissection")

local function optional_field(name)
    local ok, value = pcall(function() return Field.new(name) end)
    return ok and value or nil
end

local can_id_field = optional_field("can.id")
local can_len_field = optional_field("can.len")
local can_xtd_field = optional_field("can.flags.xtd")
local can_rtr_field = optional_field("can.flags.rtr")
local can_err_field = optional_field("can.flags.err")
local can_fd_field = optional_field("canfd.flags.fdf")
local can_bus_field = optional_field("can.bus_id")
local interface_field = optional_field("frame.interface_id")

local function field_value(extractor)
    if extractor == nil then return nil end
    local info = extractor()
    if info == nil then return nil end
    local ok, value = pcall(function() return info() end)
    if ok then return value end
    return info.value
end

local function field_number(extractor)
    local value = field_value(extractor)
    if type(value) == "boolean" then return value and 1 or 0 end
    return value ~= nil and tonumber(value) or nil
end

local function add_generated(tree, field, value)
    local item = tree:add(field, value)
    item:set_generated()
    return item
end

local function add_expert(item, which, _range, message)
    item:add_proto_expert_info(which, message)
end

local function u32le(raw, offset)
    local a, b, c, d = string.byte(raw, offset + 1, offset + 4)
    if d == nil then return nil end
    return a | (b << 8) | (c << 16) | (d << 24)
end

local function u48le(raw, offset)
    local out = 0
    for i = 5, 0, -1 do
        local byte = string.byte(raw, offset + i + 1)
        if byte == nil then return nil end
        out = (out << 8) | byte
    end
    return out
end

local function u64_new(lo, hi)
    return { lo = lo & 0xFFFFFFFF, hi = hi & 0xFFFFFFFF }
end

local function u64_from_le(raw, offset)
    local lo = u32le(raw, offset)
    local hi = u32le(raw, offset + 4)
    return (lo ~= nil and hi ~= nil) and u64_new(lo, hi) or nil
end

local function u64_xor(a, b)
    return u64_new(a.lo ~ b.lo, a.hi ~ b.hi)
end

local function u64_xor_small(a, value)
    return u64_new(a.lo ~ value, a.hi)
end

local function u64_equal(a, b)
    return a.lo == b.lo and a.hi == b.hi
end

local function u64_hex(value)
    return string.format("%08x%08x", value.hi, value.lo)
end

local function u64_mod(value, modulus)
    local limbs = {
        value.hi >> 16, value.hi & 0xFFFF,
        value.lo >> 16, value.lo & 0xFFFF,
    }
    local out = 0
    for _, limb in ipairs(limbs) do out = ((out * 65536) + limb) % modulus end
    return out
end

local function u64_mul_128(a, b)
    local aa = { a.lo & 0xFFFF, a.lo >> 16, a.hi & 0xFFFF, a.hi >> 16 }
    local bb = { b.lo & 0xFFFF, b.lo >> 16, b.hi & 0xFFFF, b.hi >> 16 }
    local product = { 0, 0, 0, 0, 0, 0, 0, 0 }
    for i = 1, 4 do
        for j = 1, 4 do product[i + j - 1] = product[i + j - 1] + aa[i] * bb[j] end
    end
    for i = 1, 7 do
        local carry = product[i] // 65536
        product[i] = product[i] % 65536
        product[i + 1] = product[i + 1] + carry
    end
    product[8] = product[8] % 65536
    local lo = u64_new(product[1] | (product[2] << 16), product[3] | (product[4] << 16))
    local hi = u64_new(product[5] | (product[6] << 16), product[7] | (product[8] << 16))
    return lo, hi
end

local function rapid_mix(a, b)
    local lo, hi = u64_mul_128(a, b)
    return u64_xor(lo, hi)
end

local rapid_secret = {
    u64_new(0xAA6C78A5, 0x2D358DCC), u64_new(0x962EACC9, 0x8BB84B93),
    u64_new(0xD433D4A3, 0x4B33A62E), u64_new(0x1DE1AA47, 0x4D5A2DA5),
    u64_new(0x78BD642F, 0xA0761D64), u64_new(0xA0B428DB, 0xE7037ED1),
    u64_new(0x281C388C, 0x90ED1765), u64_new(0xAAAAAAAA, 0xAAAAAAAA),
}

local function rapid_read64(raw, offset)
    return u64_from_le(raw, offset)
end

local function rapid_read32(raw, offset)
    return u64_new(u32le(raw, offset), 0)
end

local function rapidhash(raw)
    local length = #raw
    local seed = rapid_mix(rapid_secret[3], rapid_secret[2])
    local a, b = u64_new(0, 0), u64_new(0, 0)
    local offset, remaining = 0, length
    if length <= 16 then
        if length >= 4 then
            seed = u64_xor_small(seed, length)
            if length >= 8 then
                a = rapid_read64(raw, 0)
                b = rapid_read64(raw, length - 8)
            else
                a = rapid_read32(raw, 0)
                b = rapid_read32(raw, length - 4)
            end
        elseif length > 0 then
            local first = string.byte(raw, 1)
            local last = string.byte(raw, length)
            local middle = string.byte(raw, (length >> 1) + 1)
            a = u64_new(last, first << 13) -- first << 45
            b = u64_new(middle, 0)
        end
    else
        if length > 112 then
            local see1, see2, see3 = seed, seed, seed
            local see4, see5, see6 = seed, seed, seed
            repeat
                seed = rapid_mix(u64_xor(rapid_read64(raw, offset), rapid_secret[1]),
                                 u64_xor(rapid_read64(raw, offset + 8), seed))
                see1 = rapid_mix(u64_xor(rapid_read64(raw, offset + 16), rapid_secret[2]),
                                 u64_xor(rapid_read64(raw, offset + 24), see1))
                see2 = rapid_mix(u64_xor(rapid_read64(raw, offset + 32), rapid_secret[3]),
                                 u64_xor(rapid_read64(raw, offset + 40), see2))
                see3 = rapid_mix(u64_xor(rapid_read64(raw, offset + 48), rapid_secret[4]),
                                 u64_xor(rapid_read64(raw, offset + 56), see3))
                see4 = rapid_mix(u64_xor(rapid_read64(raw, offset + 64), rapid_secret[5]),
                                 u64_xor(rapid_read64(raw, offset + 72), see4))
                see5 = rapid_mix(u64_xor(rapid_read64(raw, offset + 80), rapid_secret[6]),
                                 u64_xor(rapid_read64(raw, offset + 88), see5))
                see6 = rapid_mix(u64_xor(rapid_read64(raw, offset + 96), rapid_secret[7]),
                                 u64_xor(rapid_read64(raw, offset + 104), see6))
                offset = offset + 112
                remaining = remaining - 112
            until remaining <= 112
            seed = u64_xor(seed, see1)
            see2 = u64_xor(see2, see3)
            see4 = u64_xor(see4, see5)
            seed = u64_xor(seed, see6)
            see2 = u64_xor(see2, see4)
            seed = u64_xor(seed, see2)
        end
        if remaining > 16 then
            seed = rapid_mix(u64_xor(rapid_read64(raw, offset), rapid_secret[3]),
                             u64_xor(rapid_read64(raw, offset + 8), seed))
            if remaining > 32 then
                seed = rapid_mix(u64_xor(rapid_read64(raw, offset + 16), rapid_secret[3]),
                                 u64_xor(rapid_read64(raw, offset + 24), seed))
                if remaining > 48 then
                    seed = rapid_mix(u64_xor(rapid_read64(raw, offset + 32), rapid_secret[2]),
                                     u64_xor(rapid_read64(raw, offset + 40), seed))
                    if remaining > 64 then
                        seed = rapid_mix(u64_xor(rapid_read64(raw, offset + 48), rapid_secret[2]),
                                         u64_xor(rapid_read64(raw, offset + 56), seed))
                        if remaining > 80 then
                            seed = rapid_mix(u64_xor(rapid_read64(raw, offset + 64), rapid_secret[3]),
                                             u64_xor(rapid_read64(raw, offset + 72), seed))
                            if remaining > 96 then
                                seed = rapid_mix(u64_xor(rapid_read64(raw, offset + 80), rapid_secret[2]),
                                                 u64_xor(rapid_read64(raw, offset + 88), seed))
                            end
                        end
                    end
                end
            end
        end
        a = u64_xor_small(rapid_read64(raw, offset + remaining - 16), remaining)
        b = rapid_read64(raw, offset + remaining - 8)
    end
    a = u64_xor(a, rapid_secret[2])
    b = u64_xor(b, seed)
    a, b = u64_mul_128(a, b)
    return rapid_mix(u64_xor(a, rapid_secret[8]), u64_xor_small(u64_xor(b, rapid_secret[2]), remaining))
end

local function crc16_ccitt(raw)
    local crc = 0xFFFF
    for i = 1, #raw do
        crc = crc ~ (string.byte(raw, i) << 8)
        for _ = 1, 8 do
            crc = ((crc & 0x8000) ~= 0) and (((crc << 1) ~ 0x1021) & 0xFFFF) or ((crc << 1) & 0xFFFF)
        end
    end
    return crc
end

local crc32c_table = {}
for index = 0, 255 do
    local crc = index
    for _ = 1, 8 do crc = ((crc & 1) ~= 0) and ((crc >> 1) ~ 0x82F63B78) or (crc >> 1) end
    crc32c_table[index] = crc & 0xFFFFFFFF
end

local function crc32c_add(crc, raw)
    for i = 1, #raw do
        local index = (crc ~ string.byte(raw, i)) & 0xFF
        crc = ((crc >> 8) ~ crc32c_table[index]) & 0xFFFFFFFF
    end
    return crc
end

local function crc32c(raw)
    local crc = crc32c_add(0xFFFFFFFF, raw)
    return (crc ~ 0xFFFFFFFF) & 0xFFFFFFFF
end

local function calculated_subject(hash, evictions, modulus)
    if evictions >= EVICTIONS_PINNED_MIN then
        return 0xFFFFFFFF - evictions, true
    end
    local h = u64_mod(hash, modulus)
    local e = evictions % modulus
    return SUBJECT_ID_PINNED_MAX + 1 + ((h + ((e * e) % modulus)) % modulus), false
end

local function bytes_are_zero(raw)
    for i = 1, #raw do if string.byte(raw, i) ~= 0 then return false end end
    return true
end

local function printable(raw)
    return (raw:gsub("[^!-~]", "."))
end

local function normalized_name(raw)
    for i = 1, #raw do
        local b = string.byte(raw, i)
        if b < 33 or b > 126 then return nil end
    end
    local parts = {}
    for part in raw:gmatch("[^/]+") do parts[#parts + 1] = part end
    return table.concat(parts, "/")
end

-- Gossip maps topic hashes to names. A subject-ID alone is insufficient because
-- distributed allocation permits the same topic to move between subjects.
local topic_names = {}

local function learn_topic_name(hash, name)
    local key = u64_hex(hash)
    local known = topic_names[key]
    if known == nil then
        topic_names[key] = { name = name, ambiguous = false }
    elseif known.name ~= name then
        known.ambiguous = true
    end
end

local function resolve_topic_name(hash)
    if hash == nil then return nil end
    local known = topic_names[u64_hex(hash)]
    if known == nil or known.ambiguous then return nil end
    return known.name
end

local function scope_for(meta)
    if meta.service then return "unicast" end
    if meta.subject_id == meta.broadcast_subject_id then return "broadcast" end
    if meta.subject_id >= meta.gossip_first then return "sharded" end
    return "multicast"
end

local function source_text(meta)
    return meta.anonymous and "anon" or tostring(meta.source)
end

local function destination_text(meta)
    if meta.service then return string.format("N%d", meta.destination) end
    if meta.subject_id == meta.broadcast_subject_id then return string.format("S%08x/BCAST", meta.subject_id) end
    if meta.subject_id >= meta.gossip_first then
        return string.format("S%08x/G%0" .. meta.gossip_digits .. "d",
            meta.subject_id, meta.subject_id - meta.gossip_first)
    end
    return string.format("S%08x", meta.subject_id)
end

local function named_topic_destination(meta, name)
    return string.format("%s →S%08x", name, meta.subject_id)
end

local function info_context(meta)
    return string.format("prio=%d tid=%d", meta.priority, meta.transfer_id or 0)
end

local function classify_identifier(can_id)
    local meta = {
        can_id = can_id & 0x1FFFFFFF,
        priority = (can_id >> 26) & 7,
        service = ((can_id >> 25) & 1) ~= 0,
        errors = {},
        subject_id_modulus = CAN_SUBJECT_ID_MODULUS,
        gossip_first = CAN_SUBJECT_ID_GOSSIP_FIRST,
        gossip_count = CAN_SUBJECT_ID_GOSSIP_COUNT,
        gossip_digits = 3,
        broadcast_subject_id = CAN_SUBJECT_ID_BROADCAST,
    }
    if meta.service then
        meta.request = ((can_id >> 24) & 1) ~= 0
        meta.reserved = (can_id >> 23) & 1
        meta.service_id = (can_id >> 14) & 0x1FF
        meta.destination = (can_id >> 7) & 0x7F
        meta.source = can_id & 0x7F
        meta.kind = meta.request and "service request" or "service response"
        meta.session = meta.request and meta.service_id == UNICAST_SERVICE_ID
        meta.version = meta.session and "1.1" or "1.0"
        if meta.reserved ~= 0 then meta.errors[#meta.errors + 1] = { "noncanonical", "Reserved service bit 23 is nonzero" } end
        if meta.source == meta.destination then meta.errors[#meta.errors + 1] = { "malformed", "Self-addressed service transfer" } end
    else
        meta.source = can_id & 0x7F
        if ((can_id >> 7) & 1) ~= 0 then
            meta.version = "1.1"
            meta.kind = "16-bit message"
            meta.subject_id = (can_id >> 8) & 0xFFFF
            meta.reserved = (can_id >> 24) & 1
            meta.session = true
            if meta.reserved ~= 0 then meta.errors[#meta.errors + 1] = { "noncanonical", "Reserved v1.1 message bit 24 is nonzero" } end
        else
            meta.version = "1.0"
            meta.kind = "13-bit message"
            meta.anonymous = ((can_id >> 24) & 1) ~= 0
            meta.reserved = (can_id >> 23) & 1
            meta.v10_fixed = (can_id >> 21) & 3
            meta.subject_id = (can_id >> 8) & 0x1FFF
            meta.discriminator = can_id & 0x7F
            meta.session = false
            if meta.reserved ~= 0 or meta.v10_fixed ~= 3 then
                meta.errors[#meta.errors + 1] = { "noncanonical", "Non-canonical v1.0 message fixed/reserved bits" }
            end
        end
    end
    meta.scope = scope_for(meta)
    return meta
end

local reassembly_sessions = {}
local frame_results = {}
local udp_reassembly_sessions = {}
local udp_completed_transfers = {}
local udp_frame_results = {}
local udp_active_transfer_count = 0
local udp_buffered_bytes = 0
local udp_cached_payload_bytes = 0
local udp_payload_cache = {}
local udp_payload_cache_head = 1
local udp_payload_cache_tail = 0
local session_colors_installed = false

local function install_session_colors()
    if session_colors_installed or not gui_enabled() then return end
    -- Set the guard first because changing a color filter can initiate another
    -- dissection pass, whose init callback must not reinstall the rules.
    session_colors_installed = true
    for slot = 1, 10 do
        set_color_filter_slot(slot, string.format(
            "cyphalcan11.session_color == %d || cyphaludp11.session_color == %d", slot, slot))
    end
end

local function timestamp_number(pinfo)
    return tonumber(tostring(pinfo.abs_ts)) or tonumber(tostring(pinfo.rel_ts)) or 0
end

local function interface_key()
    return tostring(field_number(interface_field) or "-") .. ":" .. tostring(field_number(can_bus_field) or "-")
end

local function session_color_slot(meta)
    -- Include both capture-interface and CAN-bus metadata in the interface
    -- identity. The fixed-width CAN-ID suffix keeps the serialized tuple
    -- unambiguous, and rapidhash provides stable mixing across the ten slots.
    local key = interface_key() .. "/" .. string.format("%08x", meta.can_id)
    return 1 + u64_mod(rapidhash(key), 10)
end

local function ipv4_number(address)
    local a, b, c, d = tostring(address):match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    if a == nil or a > 255 or b > 255 or c > 255 or d > 255 then return nil end
    return (a << 24) | (b << 16) | (c << 8) | d
end

local function endpoint_text(address, port)
    return string.format("%s:%d", tostring(address), tonumber(port) or 0)
end

local function udp_port_key(meta)
    -- A unicast receive port pools redundant interfaces. Its IP endpoints are
    -- reverse-path metadata, not part of the transfer/session identity.
    if meta.scope == "unicast" then return "U" end
    return string.format("S%08x", meta.subject_id)
end

local function udp_transfer_key(meta)
    return string.format("%s/%s/%012x", udp_port_key(meta), u64_hex(meta.sender_uid), meta.transfer_id)
end

local function udp_color_slot(meta)
    local key = string.format("%s/%s", udp_port_key(meta), u64_hex(meta.sender_uid))
    return 1 + u64_mod(rapidhash(key), 10)
end

local function transfer_key(meta)
    local port = meta.service and ("V" .. meta.service_id .. ":" .. (meta.request and "Q" or "P") .. ":" .. meta.destination)
        or ("S" .. meta.subject_id .. ":" .. (meta.anonymous and ("A" .. meta.discriminator) or "N"))
    return table.concat({ interface_key(), meta.version, port, meta.source, meta.priority }, "/")
end

local function expire_reassembly(now)
    for key, state in pairs(reassembly_sessions) do
        if (now - state.updated) > REASSEMBLY_TIMEOUT_SECONDS then reassembly_sessions[key] = nil end
    end
end

local function expire_udp_reassembly(now)
    for key, state in pairs(udp_reassembly_sessions) do
        if (now - state.updated) > REASSEMBLY_TIMEOUT_SECONDS then
            udp_buffered_bytes = math.max(0, udp_buffered_bytes - state.buffered_bytes)
            udp_active_transfer_count = math.max(0, udp_active_transfer_count - 1)
            udp_reassembly_sessions[key] = nil
        end
    end
    for key, state in pairs(udp_completed_transfers) do
        if (now - state.updated) > REASSEMBLY_TIMEOUT_SECONDS then udp_completed_transfers[key] = nil end
    end
end

-- Active transfers retain an AVL tree of disjoint byte ranges. New fragments
-- are trimmed against existing ranges before insertion, so the stored payload
-- can never exceed the advertised transfer size and lookup remains logarithmic.
local udp_ranges = {}

function udp_ranges.height(node) return node == nil and 0 or node.height end

function udp_ranges.update(node)
    node.height = 1 + math.max(udp_ranges.height(node.left), udp_ranges.height(node.right))
    return node
end

function udp_ranges.rotate_left(root)
    local pivot = root.right
    root.right, pivot.left = pivot.left, root
    udp_ranges.update(root)
    return udp_ranges.update(pivot)
end

function udp_ranges.rotate_right(root)
    local pivot = root.left
    root.left, pivot.right = pivot.right, root
    udp_ranges.update(root)
    return udp_ranges.update(pivot)
end

function udp_ranges.insert(root, node)
    if root == nil then return node end
    if node.offset < root.offset then root.left = udp_ranges.insert(root.left, node)
    else root.right = udp_ranges.insert(root.right, node) end
    udp_ranges.update(root)
    local balance = udp_ranges.height(root.left) - udp_ranges.height(root.right)
    if balance > 1 then
        if node.offset > root.left.offset then root.left = udp_ranges.rotate_left(root.left) end
        return udp_ranges.rotate_right(root)
    end
    if balance < -1 then
        if node.offset < root.right.offset then root.right = udp_ranges.rotate_right(root.right) end
        return udp_ranges.rotate_left(root)
    end
    return root
end

function udp_ranges.collect_overlaps(node, first, after, out)
    if node == nil then return end
    local node_after = node.offset + #node.data
    if node.offset >= after then
        udp_ranges.collect_overlaps(node.left, first, after, out)
    elseif node_after <= first then
        udp_ranges.collect_overlaps(node.right, first, after, out)
    else
        udp_ranges.collect_overlaps(node.left, first, after, out)
        out[#out + 1] = node
        udp_ranges.collect_overlaps(node.right, first, after, out)
    end
end

function udp_ranges.uncovered(root, offset, data)
    local after = offset + #data
    local overlaps = {}
    udp_ranges.collect_overlaps(root, offset, after, overlaps)
    local pieces, cursor, overlaps_good = {}, offset, true
    for _, node in ipairs(overlaps) do
        if node.offset > cursor then
            local gap_after = math.min(node.offset, after)
            pieces[#pieces + 1] = {
                offset = cursor,
                data = data:sub(cursor - offset + 1, gap_after - offset),
                height = 1,
            }
            cursor = gap_after
        end
        local overlap_first = math.max(offset, node.offset)
        local overlap_after = math.min(after, node.offset + #node.data)
        if data:sub(overlap_first - offset + 1, overlap_after - offset) ~=
           node.data:sub(overlap_first - node.offset + 1, overlap_after - node.offset) then
            overlaps_good = false
        end
        cursor = math.max(cursor, node.offset + #node.data)
    end
    if cursor < after then
        pieces[#pieces + 1] = {
            offset = cursor,
            data = data:sub(cursor - offset + 1),
            height = 1,
        }
    end
    return pieces, overlaps_good
end

function udp_ranges.assemble(root, total_size)
    local pieces, cursor, valid = {}, 0, true
    local function visit(node)
        if node == nil or not valid then return end
        visit(node.left)
        if node.offset ~= cursor then valid = false return end
        pieces[#pieces + 1] = node.data
        cursor = cursor + #node.data
        visit(node.right)
    end
    visit(root)
    if not valid or cursor ~= total_size then return nil end
    return table.concat(pieces)
end

local function release_udp_state(key)
    local state = udp_reassembly_sessions[key]
    if state ~= nil then
        udp_buffered_bytes = math.max(0, udp_buffered_bytes - state.buffered_bytes)
        udp_active_transfer_count = math.max(0, udp_active_transfer_count - 1)
        udp_reassembly_sessions[key] = nil
    end
    return state
end

local function populate_udp_prefix_results(state, payload)
    local endpoints, seen = {}, {}
    for _, frame_number in ipairs(state.frames) do
        local frame_result = udp_frame_results[frame_number]
        if frame_result ~= nil and not seen[frame_result.payload_end] then
            seen[frame_result.payload_end] = true
            endpoints[#endpoints + 1] = frame_result.payload_end
        end
    end
    table.sort(endpoints)
    local cursor, crc, values = 0, 0xFFFFFFFF, {}
    for _, payload_end in ipairs(endpoints) do
        crc = crc32c_add(crc, payload:sub(cursor + 1, payload_end))
        values[payload_end] = (crc ~ 0xFFFFFFFF) & 0xFFFFFFFF
        cursor = payload_end
    end
    for _, frame_number in ipairs(state.frames) do
        local frame_result = udp_frame_results[frame_number]
        if frame_result ~= nil then
            frame_result.prefix_crc_calculated = values[frame_result.payload_end]
            frame_result.prefix_crc_good = frame_result.prefix_crc_calculated == frame_result.prefix_crc
            if not frame_result.prefix_crc_good then
                frame_result.errors[#frame_result.errors + 1] = { "prefix_crc", "Payload prefix CRC-32C mismatch" }
            end
        end
    end
    return values[state.total_size]
end

local function cacheable_session_prefix(payload)
    if #payload <= SESSION_HEADER_SIZE then return payload end
    local session_type = string.byte(payload, 1)
    local keep = SESSION_HEADER_SIZE
    if session_type == 8 or session_type == 9 then
        keep = math.min(#payload, SESSION_HEADER_SIZE + TOPIC_NAME_MAX)
    end
    return payload:sub(1, keep)
end

local function retain_udp_result_payload(result)
    if result.payload == nil or result.payload_cache_size ~= nil then return end
    result.session_size = #result.payload
    result.session_prefix = cacheable_session_prefix(result.payload)
    result.payload_cache_size = #result.payload
    udp_cached_payload_bytes = udp_cached_payload_bytes + result.payload_cache_size
    udp_payload_cache_tail = udp_payload_cache_tail + 1
    udp_payload_cache[udp_payload_cache_tail] = result
    local limit = cyphal_udp.prefs.max_cached_payload_bytes
    while udp_cached_payload_bytes > limit and udp_payload_cache_head <= udp_payload_cache_tail do
        local oldest = udp_payload_cache[udp_payload_cache_head]
        udp_payload_cache[udp_payload_cache_head] = nil
        udp_payload_cache_head = udp_payload_cache_head + 1
        if oldest ~= nil and oldest.payload ~= nil then
            udp_cached_payload_bytes = math.max(0, udp_cached_payload_bytes - oldest.payload_cache_size)
            oldest.payload = nil
        end
    end
    if udp_payload_cache_head > udp_payload_cache_tail then
        udp_payload_cache, udp_payload_cache_head, udp_payload_cache_tail = {}, 1, 0
    end
end

local function process_udp_reassembly(meta, pinfo)
    local cached = udp_frame_results[pinfo.number]
    if cached ~= nil then return cached end

    local result = {
        errors = {}, sot = meta.sot, eot = meta.eot, transfer_id = meta.transfer_id,
        frame_offset = meta.frame_offset, payload_end = meta.frame_offset + #meta.frame_payload,
        prefix_crc = meta.prefix_crc, fragment_count = 1,
    }
    udp_frame_results[pinfo.number] = result
    local key = udp_transfer_key(meta)
    result.transfer_key = key

    if meta.frame_offset == 0 then
        result.prefix_crc_calculated = crc32c(meta.frame_payload)
        result.prefix_crc_good = result.prefix_crc_calculated == result.prefix_crc
        if not result.prefix_crc_good then
            result.errors[#result.errors + 1] = { "prefix_crc", "First-frame payload prefix CRC-32C mismatch" }
            return result
        end
    end

    local now = timestamp_number(pinfo)
    expire_udp_reassembly(now)
    local completed = udp_completed_transfers[key]
    if completed ~= nil then
        result.duplicate = true
        result.fragment_count = completed.fragment_count
        result.reassembled_in = completed.reassembled_in
        result.reassembled_length = completed.size
        result.topic_hash = completed.topic_hash
        if meta.transfer_payload_size ~= completed.size or meta.priority ~= completed.priority then
            result.errors[#result.errors + 1] = { "reassembly", "Duplicate frame is inconsistent with the completed transfer" }
        elseif result.payload_end == completed.size then
            result.prefix_crc_calculated = completed.final_crc
            result.prefix_crc_good = result.prefix_crc_calculated == result.prefix_crc
            if not result.prefix_crc_good then
                result.errors[#result.errors + 1] = { "prefix_crc", "Duplicate frame payload prefix CRC-32C mismatch" }
            end
        end
        return result
    end

    local state = udp_reassembly_sessions[key]
    if state == nil then
        if udp_active_transfer_count >= cyphal_udp.prefs.max_active_transfers then
            result.errors[#result.errors + 1] = { "reassembly", "Too many active UDP transfers" }
            return result
        end
        state = {
            total_size = meta.transfer_payload_size, priority = meta.priority,
            frames = {}, range_root = nil, buffered_bytes = 0, frame_count = 0, updated = now,
        }
        udp_reassembly_sessions[key] = state
        udp_active_transfer_count = udp_active_transfer_count + 1
    elseif state.total_size ~= meta.transfer_payload_size or state.priority ~= meta.priority then
        result.errors[#result.errors + 1] = { "reassembly", "Inconsistent metadata within a UDP transfer" }
        release_udp_state(key)
        return result
    end
    state.updated = now
    state.frame_count = state.frame_count + 1
    if state.frame_count > cyphal_udp.prefs.max_fragments then
        result.errors[#result.errors + 1] = { "reassembly", "UDP transfer exceeds the fragment-count limit" }
        release_udp_state(key)
        return result
    end

    local pieces, overlaps_good = udp_ranges.uncovered(state.range_root, meta.frame_offset, meta.frame_payload)
    local added_bytes = 0
    for _, piece in ipairs(pieces) do added_bytes = added_bytes + #piece.data end
    if not overlaps_good then
        result.errors[#result.errors + 1] = { "reassembly", "Overlapping UDP fragment contains different bytes" }
    end
    local accept_empty = state.total_size == 0 and #state.frames == 0
    if added_bytes == 0 and not accept_empty then
        result.duplicate = true
        result.fragment_count = #state.frames
        return result
    end
    if (udp_buffered_bytes + added_bytes) > cyphal_udp.prefs.max_buffered_bytes then
        result.errors[#result.errors + 1] = { "reassembly", "UDP reassembly memory limit exceeded" }
        release_udp_state(key)
        return result
    end
    for _, piece in ipairs(pieces) do state.range_root = udp_ranges.insert(state.range_root, piece) end
    state.buffered_bytes = state.buffered_bytes + added_bytes
    udp_buffered_bytes = udp_buffered_bytes + added_bytes
    state.frames[#state.frames + 1] = pinfo.number
    result.fragment_count = #state.frames
    if state.buffered_bytes < state.total_size then return result end

    local payload = udp_ranges.assemble(state.range_root, state.total_size)
    if payload == nil then return result end
    release_udp_state(key)
    result.complete = true
    result.payload = payload
    result.frames = state.frames
    result.reassembled_length = #payload
    local full_crc_calculated = populate_udp_prefix_results(state, payload)
    local full_crc_expected
    for _, frame_number in ipairs(state.frames) do
        local frame_result = udp_frame_results[frame_number]
        if frame_result ~= nil and frame_result.eot then full_crc_expected = frame_result.prefix_crc end
    end
    result.transfer_crc_good = full_crc_expected ~= nil and full_crc_calculated == full_crc_expected
    if not result.transfer_crc_good then
        result.errors[#result.errors + 1] = { "prefix_crc", "Reassembled transfer CRC-32C mismatch" }
    end
    for _, frame_number in ipairs(state.frames) do
        local frame_result = udp_frame_results[frame_number]
        if frame_result ~= nil then
            frame_result.fragment_count = #state.frames
            frame_result.reassembled_in = pinfo.number
            frame_result.reassembled_length = #payload
        end
    end
    if result.transfer_crc_good then
        udp_completed_transfers[key] = {
            size = #payload, priority = state.priority, fragment_count = #state.frames,
            final_crc = full_crc_calculated,
            reassembled_in = pinfo.number, updated = now,
        }
    end
    return result
end

local function complete_multiframe(state, result)
    local raw = state.data
    if #raw < 2 then
        result.errors[#result.errors + 1] = { "reassembly", "Multiframe transfer is shorter than its CRC" }
        result.payload = ""
        return
    end
    result.crc = (string.byte(raw, #raw - 1) << 8) | string.byte(raw, #raw)
    result.payload = raw:sub(1, #raw - 2)
    result.crc_calculated = crc16_ccitt(result.payload)
    result.crc_good = result.crc == result.crc_calculated
    if not result.crc_good then result.errors[#result.errors + 1] = { "crc", "Transfer CRC mismatch" } end
end

local function process_reassembly(tvb, pinfo, meta)
    local cached = frame_results[pinfo.number]
    if cached ~= nil then return cached end

    local result = { errors = {}, fragment_count = 1, fragment_index = 0 }
    frame_results[pinfo.number] = result
    local length = tvb:len()
    if length < 1 then
        result.errors[#result.errors + 1] = { "malformed", "CAN data frame has no tail byte" }
        return result
    end

    local tail = tvb(length - 1, 1):uint()
    local sot = (tail & 0x80) ~= 0
    local eot = (tail & 0x40) ~= 0
    local toggle = (tail & 0x20) ~= 0
    local transfer_id = tail & 0x1F
    local fragment = tvb:raw(0, length - 1)
    result.tail, result.sot, result.eot = tail, sot, eot
    result.toggle, result.transfer_id = toggle, transfer_id

    if length > 64 or ({ [0] = true, [1] = true, [2] = true, [3] = true, [4] = true, [5] = true,
                         [6] = true, [7] = true, [8] = true, [12] = true, [16] = true, [20] = true,
                         [24] = true, [32] = true, [48] = true, [64] = true })[length] ~= true then
        result.errors[#result.errors + 1] = { "malformed", "Illegal classic-CAN/CAN-FD data length" }
    end
    local full_mtu = meta.can_fd and 64 or 8
    if not eot and length ~= full_mtu then
        result.errors[#result.errors + 1] = { "malformed", "Non-final frame does not use a full CAN MTU" }
    end
    if sot and not toggle then
        result.errors[#result.errors + 1] = { "sequence", "Cyphal v1 transfers must start with toggle=1" }
    end
    if meta.anonymous and not (sot and eot) then
        result.errors[#result.errors + 1] = { "sequence", "Anonymous transfers must be single-frame" }
        return result
    end
    if sot and eot then
        result.payload = fragment
        result.complete = true
        result.single = true
        result.reassembled_length = #fragment
        return result
    end

    local now = timestamp_number(pinfo)
    expire_reassembly(now)
    local key = transfer_key(meta)
    if sot then
        local previous = reassembly_sessions[key]
        if previous ~= nil then
            local prior = frame_results[previous.frames[#previous.frames]]
            if prior ~= nil then prior.errors[#prior.errors + 1] = { "sequence", "Transfer superseded by a new start frame" } end
        end
        local state = {
            data = fragment,
            transfer_id = transfer_id,
            expected_toggle = not toggle,
            updated = now,
            frames = { pinfo.number },
        }
        if #fragment > cyphal_can.prefs.max_reassembly_bytes then
            result.errors[#result.errors + 1] = { "reassembly", "Transfer exceeds the configured reassembly limit" }
        else
            reassembly_sessions[key] = state
        end
        result.fragment = true
        return result
    end

    local state = reassembly_sessions[key]
    if state == nil then
        result.errors[#result.errors + 1] = { "sequence", "Orphan continuation/end frame" }
        return result
    end
    if transfer_id ~= state.transfer_id then
        result.errors[#result.errors + 1] = { "sequence", "Continuation transfer-ID mismatch" }
        return result
    end
    if toggle ~= state.expected_toggle then
        result.errors[#result.errors + 1] = { "sequence", "Continuation toggle mismatch" }
        return result
    end
    if (#state.data + #fragment) > cyphal_can.prefs.max_reassembly_bytes then
        reassembly_sessions[key] = nil
        result.errors[#result.errors + 1] = { "reassembly", "Transfer exceeds the configured reassembly limit" }
        return result
    end
    state.data = state.data .. fragment
    state.expected_toggle = not state.expected_toggle
    state.updated = now
    state.frames[#state.frames + 1] = pinfo.number
    result.fragment_index = #state.frames - 1
    result.fragment_count = #state.frames
    if not eot then
        result.fragment = true
        return result
    end

    reassembly_sessions[key] = nil
    result.complete = true
    result.frames = state.frames
    complete_multiframe(state, result)
    result.reassembled_length = #result.payload
    for _, frame_number in ipairs(state.frames) do
        local frame_result = frame_results[frame_number]
        if frame_result ~= nil then
            frame_result.fragment_count = #state.frames
            frame_result.reassembled_in = pinfo.number
        end
    end
    return result
end

local function add_control_suffix(session_tree, tvb, offset)
    if offset >= tvb:len() then return end
    local range = tvb(offset, tvb:len() - offset)
    if bytes_are_zero(range:raw()) then session_tree:add(sf_padding, range)
    else session_tree:add(sf_trailing, range) end
end

local function add_session_expert(item, which, tvb, text)
    add_expert(item, which, tvb(), text)
end

local function add_topic_fields(item, tvb, raw, hash_offset, evictions, meta)
    item:add_le(sf_topic_hash, tvb(hash_offset, 8))
    local hash = u64_from_le(raw, hash_offset)
    local expected, pinned = calculated_subject(hash, evictions, meta.subject_id_modulus)
    add_generated(item, sf_expected_subject, expected)
    add_generated(item, sf_pinned, pinned)
    return hash, expected
end

local function annotate_topic(item, pinfo, meta, hash)
    meta.topic_hash = hash
    local name = resolve_topic_name(hash)
    if name ~= nil then
        add_generated(item, sf_resolved_topic_name, name)
        if meta.scope == "multicast" then pinfo.cols.dst = named_topic_destination(meta, name) end
    end
end

local function dissect_session(tvb, pinfo, tree, meta)
    local item = tree:add(cyphal_session, tvb(), "Cyphal v1.1 Session")
    local session_size = meta.session_payload_size or tvb:len()
    add_generated(item, sf_scope, meta.scope)
    if tvb:len() < SESSION_HEADER_SIZE then
        if tvb:len() > 0 then item:add(sf_type, tvb(0, 1)) end
        add_session_expert(item, ex_session_malformed, tvb, "Session header is shorter than 24 bytes")
        if tvb:len() > 1 then item:add(sf_raw_body, tvb(1, tvb:len() - 1)) end
        return string.format("⚠️ v1.1 %s short=%d B", info_context(meta), tvb:len())
    end

    local raw = tvb:raw()
    local session_type = string.byte(raw, 1)
    item:add(sf_type, tvb(0, 1))
    local type_name = session_type_names[session_type]
    if type_name == nil then
        add_session_expert(item, ex_session_unsupported, tvb, "Unsupported session type " .. session_type)
        if tvb:len() > 1 then item:add(sf_raw_body, tvb(1, tvb:len() - 1)) end
        return string.format("⚠️ TYPE-%d %s %d B", session_type, info_context(meta), session_size - 1)
    end

    if session_type <= 1 then
        item:add(sf_void, tvb(1, 1))
        item:add(sf_incompat8, tvb(2, 1))
        item:add(sf_lage, tvb(3, 1))
        item:add_le(sf_evictions, tvb(4, 4))
        local incompatibility = string.byte(raw, 3)
        local lage = string.unpack("b", raw, 4)
        local evictions = u32le(raw, 4)
        local hash, expected = add_topic_fields(item, tvb, raw, 8, evictions, meta)
        annotate_topic(item, pinfo, meta, hash)
        item:add_le(sf_message_tag, tvb(16, 8))
        local tag = u64_from_le(raw, 16)
        if incompatibility ~= 0 then add_session_expert(item, ex_session_incompatible, tvb, "Message incompatibility byte is nonzero") end
        if lage < -1 or lage > 35 then add_session_expert(item, ex_session_malformed, tvb, "Log-age is outside [-1, 35]") end
        if meta.scope ~= "unicast" and meta.scope ~= "multicast" then
            add_session_expert(item, ex_session_scope, tvb, "Messages require unicast or a normal multicast subject")
        end
        if meta.scope == "multicast" and expected ~= meta.subject_id then
            add_session_expert(item, ex_session_mismatch, tvb, "Calculated topic subject-ID does not match the transport subject-ID")
        end
        local app_size = session_size - SESSION_HEADER_SIZE
        local available = tvb:len() - SESSION_HEADER_SIZE
        if available > 0 then item:add(sf_application_payload, tvb(SESSION_HEADER_SIZE, available)) end
        local icon = session_type == 0 and "📨 BE" or "⛓ REL"
        return string.format("%s %s T%s@S%08x tag=%s %d B", icon, info_context(meta),
            u64_hex(hash), expected, u64_hex(tag), app_size)
    end

    if session_type == 2 or session_type == 3 then
        item:add(sf_void, tvb(1, 3))
        item:add_le(sf_incompat32, tvb(4, 4))
        item:add_le(sf_topic_hash, tvb(8, 8))
        item:add_le(sf_message_tag, tvb(16, 8))
        local incompatibility = u32le(raw, 4)
        local hash = u64_from_le(raw, 8)
        annotate_topic(item, pinfo, meta, hash)
        local tag = u64_from_le(raw, 16)
        if incompatibility ~= 0 then add_session_expert(item, ex_session_incompatible, tvb, "ACK incompatibility field is nonzero") end
        if meta.scope ~= "unicast" then add_session_expert(item, ex_session_scope, tvb, "Message ACK/NACK must be unicast") end
        add_control_suffix(item, tvb, SESSION_HEADER_SIZE)
        local label = session_type == 2 and "✅ MSG-ACK" or "❌ MSG-NACK"
        return string.format("%s %s T%s tag=%s", label, info_context(meta), u64_hex(hash), u64_hex(tag))
    end

    if session_type >= 4 and session_type <= 7 then
        item:add(sf_response_tag, tvb(1, 1))
        item:add_le(sf_response_seqno, tvb(2, 6))
        item:add_le(sf_topic_hash, tvb(8, 8))
        item:add_le(sf_message_tag, tvb(16, 8))
        local response_tag = string.byte(raw, 2)
        local seqno = u48le(raw, 2)
        local hash = u64_from_le(raw, 8)
        annotate_topic(item, pinfo, meta, hash)
        local message_tag = u64_from_le(raw, 16)
        if meta.scope ~= "unicast" then add_session_expert(item, ex_session_scope, tvb, "Responses and response ACK/NACK must be unicast") end
        local labels = { [4] = "↩️ RSP", [5] = "↩️ REL-RSP", [6] = "✅ RSP-ACK", [7] = "❌ RSP-NACK" }
        local suffix = ""
        if session_type == 4 or session_type == 5 then
            local app_size = session_size - SESSION_HEADER_SIZE
            local available = tvb:len() - SESSION_HEADER_SIZE
            if available > 0 then item:add(sf_application_payload, tvb(SESSION_HEADER_SIZE, available)) end
            suffix = string.format(" %d B", app_size)
        else
            add_control_suffix(item, tvb, SESSION_HEADER_SIZE)
        end
        return string.format("%s %s T%s seq=%d rtag=%02x msg=%s%s", labels[session_type], info_context(meta),
            u64_hex(hash), seqno, response_tag, u64_hex(message_tag), suffix)
    end

    if session_type == 8 then
        item:add(sf_void, tvb(1, 2))
        item:add(sf_lage, tvb(3, 1))
        item:add_le(sf_incompat32, tvb(4, 4))
        item:add_le(sf_topic_hash, tvb(8, 8))
        item:add_le(sf_evictions, tvb(16, 4))
        item:add(sf_void, tvb(20, 3))
        item:add(sf_name_length, tvb(23, 1))
        local lage = string.unpack("b", raw, 4)
        local incompatibility = u32le(raw, 4)
        local hash = u64_from_le(raw, 8)
        meta.topic_hash = hash
        local evictions = u32le(raw, 16)
        local name_length = string.byte(raw, 24)
        local expected, pinned = calculated_subject(hash, evictions, meta.subject_id_modulus)
        add_generated(item, sf_expected_subject, expected)
        add_generated(item, sf_pinned, pinned)
        if incompatibility ~= 0 then add_session_expert(item, ex_session_incompatible, tvb, "Gossip incompatibility field is nonzero") end
        if lage < -1 or lage > 35 then add_session_expert(item, ex_session_malformed, tvb, "Log-age is outside [-1, 35]") end
        if name_length > TOPIC_NAME_MAX or SESSION_HEADER_SIZE + name_length > tvb:len() then
            add_session_expert(item, ex_session_malformed, tvb, "Gossip topic name is truncated or too long")
            if tvb:len() > SESSION_HEADER_SIZE then item:add(sf_raw_body, tvb(SESSION_HEADER_SIZE, tvb:len() - SESSION_HEADER_SIZE)) end
            return string.format("📢 GOSSIP %s T%s name=truncated", info_context(meta), u64_hex(hash))
        end
        local name = tvb:raw(SESSION_HEADER_SIZE, name_length)
        if name_length > 0 then item:add(sf_topic_name, tvb(SESSION_HEADER_SIZE, name_length), name) end
        if meta.scope ~= "unicast" and meta.scope ~= "sharded" and meta.scope ~= "broadcast" then
            add_session_expert(item, ex_session_scope, tvb, "Gossip requires unicast, a gossip shard, or broadcast")
        end
        local gossip_subject = meta.gossip_first + u64_mod(hash, meta.gossip_count)
        add_generated(item, sf_expected_gossip, gossip_subject)
        if meta.scope == "sharded" and gossip_subject ~= meta.subject_id then
            add_session_expert(item, ex_session_mismatch, tvb, "Gossip hash maps to a different shard subject-ID")
        end
        if name_length > 0 then
            local normalized = normalized_name(name)
            if normalized == nil or normalized ~= name then
                add_session_expert(item, ex_session_mismatch, tvb, "Gossip name is not printable normalized ASCII")
            else
                local hash_good = u64_equal(rapidhash(name), hash)
                add_generated(item, sf_name_hash_good, hash_good)
                if hash_good then
                    learn_topic_name(hash, name)
                    add_generated(item, sf_resolved_topic_name, name)
                else
                    add_session_expert(item, ex_session_mismatch, tvb, "Gossip name does not match its topic hash")
                end
            end
        end
        add_control_suffix(item, tvb, SESSION_HEADER_SIZE + name_length)
        return string.format("📢 GOSSIP %s T%s@S%08x e=%u lage=%+d '%s'", info_context(meta),
            u64_hex(hash), expected, evictions, lage, printable(name):sub(1, 48))
    end

    item:add(sf_void, tvb(1, 3))
    item:add_le(sf_incompat32, tvb(4, 4))
    item:add_le(sf_incompat64, tvb(8, 8))
    item:add(sf_void, tvb(16, 7))
    item:add(sf_name_length, tvb(23, 1))
    local incompatibility0 = u32le(raw, 4)
    local incompatibility1 = u64_from_le(raw, 8)
    local pattern_length = string.byte(raw, 24)
    if incompatibility0 ~= 0 or incompatibility1.lo ~= 0 or incompatibility1.hi ~= 0 then
        add_session_expert(item, ex_session_incompatible, tvb, "Scout incompatibility fields are nonzero")
    end
    if pattern_length == 0 or pattern_length > TOPIC_NAME_MAX or SESSION_HEADER_SIZE + pattern_length > tvb:len() then
        add_session_expert(item, ex_session_malformed, tvb, "Scout pattern is empty, truncated, or too long")
        if tvb:len() > SESSION_HEADER_SIZE then item:add(sf_raw_body, tvb(SESSION_HEADER_SIZE, tvb:len() - SESSION_HEADER_SIZE)) end
        return string.format("🔎 SCOUT %s pattern=invalid", info_context(meta))
    end
    local pattern = tvb:raw(SESSION_HEADER_SIZE, pattern_length)
    item:add(sf_pattern, tvb(SESSION_HEADER_SIZE, pattern_length), pattern)
    if normalized_name(pattern) == nil then add_session_expert(item, ex_session_mismatch, tvb, "Scout pattern contains non-printable characters") end
    if meta.scope ~= "broadcast" then add_session_expert(item, ex_session_mismatch, tvb, "Scouts are conventionally broadcast") end
    add_control_suffix(item, tvb, SESSION_HEADER_SIZE + pattern_length)
    return string.format("🔎 SCOUT %s '%s'", info_context(meta), printable(pattern):sub(1, 48))
end

local transport_experts = {
    malformed = ex_can_malformed,
    sequence = ex_can_sequence,
    crc = ex_can_crc,
    noncanonical = ex_can_noncanonical,
    reassembly = ex_can_reassembly,
}

local function render_identifier(root, meta, tvb)
    add_generated(root, f_can_id, meta.can_id)
    meta.session_color = session_color_slot(meta)
    add_generated(root, f_session_color, meta.session_color)
    add_generated(root, f_version, meta.version)
    add_generated(root, f_kind, meta.kind)
    add_generated(root, f_can_fd, meta.can_fd)
    add_generated(root, f_priority, meta.priority)
    add_generated(root, f_service, meta.service)
    add_generated(root, f_reserved, meta.reserved or 0)
    if meta.service then
        add_generated(root, f_request, meta.request)
        add_generated(root, f_service_id, meta.service_id)
        add_generated(root, f_source, meta.source)
        add_generated(root, f_destination, meta.destination)
    else
        add_generated(root, f_subject_id, meta.subject_id)
        add_generated(root, f_anonymous, meta.anonymous or false)
        if meta.version == "1.0" then add_generated(root, f_v10_fixed, meta.v10_fixed) end
        if meta.anonymous then add_generated(root, f_discriminator, meta.discriminator)
        else add_generated(root, f_source, meta.source) end
    end
    for _, issue in ipairs(meta.errors) do add_expert(root, transport_experts[issue[1]], tvb(), issue[2]) end
end

local function generic_info(meta, result)
    local port = meta.service and string.format(" svc=%d %s", meta.service_id, meta.request and "REQ" or "RSP") or ""
    local size = result.payload and #result.payload or 0
    return string.format("CAN%s prio=%d tid=%d%s %d B", meta.version, meta.priority, result.transfer_id or 0, port, size)
end

local function frame_info(result, text)
    local prefix = result.sot and "🔹 " or "… "
    local suffix = result.eot and "" or " …"
    return prefix .. text .. suffix
end

local function dissect_can(tvb, pinfo, tree, heuristic)
    local can_id = field_number(can_id_field)
    local extended = field_number(can_xtd_field)
    local rtr = field_number(can_rtr_field)
    local err = field_number(can_err_field)
    if heuristic then
        if can_id == nil or extended ~= 1 or rtr == 1 or err == 1 or tvb:len() == 0 then return false end
    end

    pinfo.cols.protocol = "CYPHAL/CAN"
    local root = tree:add(cyphal_can, tvb(), "Cyphal/CAN v1")
    if can_id == nil then
        add_expert(root, ex_can_malformed, tvb(), "CAN identifier metadata is unavailable")
        pinfo.cols.info = "⚠️ Cyphal/CAN: missing CAN identifier"
        return not heuristic
    end
    local meta = classify_identifier(can_id)
    meta.can_fd = field_number(can_fd_field) == 1
    pinfo.cols.src = source_text(meta)
    pinfo.cols.dst = destination_text(meta)
    render_identifier(root, meta, tvb)

    local captured_length = tvb:len()
    local declared_length = field_number(can_len_field)
    if declared_length ~= nil and declared_length ~= captured_length then
        add_expert(root, ex_can_malformed, tvb(), "Captured CAN payload length differs from can.len")
    end
    if captured_length < 1 then
        add_expert(root, ex_can_malformed, tvb(), "CAN data frame has no tail byte")
        pinfo.cols.info = "⚠️ Cyphal/CAN empty frame"
        return true
    end
    if captured_length > 1 then root:add(f_frame_payload, tvb(0, captured_length - 1)) end
    local tail_range = tvb(captured_length - 1, 1)
    local tail_tree = root:add(cyphal_can, tail_range, "Cyphal/CAN Tail")
    tail_tree:add(f_tail, tail_range)
    tail_tree:add(f_sot, tail_range)
    tail_tree:add(f_eot, tail_range)
    tail_tree:add(f_toggle, tail_range)
    tail_tree:add(f_transfer_id, tail_range)

    local result = process_reassembly(tvb, pinfo, meta)
    add_generated(root, f_fragment_index, result.fragment_index or 0)
    add_generated(root, f_fragment_count, result.fragment_count or 1)
    if result.reassembled_in ~= nil then add_generated(root, f_reassembled_in, result.reassembled_in) end
    if result.reassembled_length ~= nil then add_generated(root, f_reassembled_length, result.reassembled_length) end
    if result.crc ~= nil then
        add_generated(root, f_crc, result.crc)
        add_generated(root, f_crc_calculated, result.crc_calculated)
        add_generated(root, f_crc_good, result.crc_good)
    end
    for _, issue in ipairs(result.errors) do add_expert(root, transport_experts[issue[1]], tvb(), issue[2]) end

    if not result.complete then
        local name = resolve_topic_name(result.topic_hash)
        if meta.scope == "multicast" and name ~= nil then pinfo.cols.dst = named_topic_destination(meta, name) end
        pinfo.cols.info = frame_info(result, string.format("CAN%s prio=%d tid=%d frag=%d", meta.version,
            meta.priority, result.transfer_id or 0, result.fragment_index or 0))
        return true
    end

    local reassembled = ByteArray.new(result.payload, true):tvb("Reassembled Cyphal/CAN transfer")
    local summary
    if meta.session then
        meta.transfer_id = result.transfer_id
        summary = dissect_session(reassembled, pinfo, root, meta)
        if meta.topic_hash ~= nil then
            result.topic_hash = meta.topic_hash
            if result.frames ~= nil then
                for _, frame_number in ipairs(result.frames) do
                    local frame_result = frame_results[frame_number]
                    if frame_result ~= nil then frame_result.topic_hash = meta.topic_hash end
                end
            end
        end
        pinfo.cols.protocol = "CYPHAL1.1"
    else
        if reassembled:len() > 0 then root:add(f_payload, reassembled()) end
        summary = generic_info(meta, result)
    end
    pinfo.cols.info = frame_info(result, summary)
    return true
end

local udp_transport_experts = {
    malformed = udp_ex.malformed,
    header_crc = udp_ex.header_crc,
    prefix_crc = udp_ex.prefix_crc,
    incompatible = udp_ex.incompatible,
    noncanonical = udp_ex.noncanonical,
    reassembly = udp_ex.reassembly,
}

local function parse_udp_header(tvb, pinfo)
    local raw = tvb:raw()
    local head, features = string.byte(raw, 1, 2)
    local meta = {
        version = head & 0x1F,
        priority = (head >> 5) & 7,
        void = features & 0x1F,
        incompatibility = (features >> 5) & 7,
        transfer_id = u48le(raw, 2),
        sender_uid = u64_from_le(raw, 8),
        frame_offset = u32le(raw, 16),
        transfer_payload_size = u32le(raw, 20),
        prefix_crc = u32le(raw, 24),
        header_crc = u32le(raw, 28),
        header_crc_calculated = crc32c(raw:sub(1, 28)),
        frame_payload = raw:sub(UDP_HEADER_SIZE + 1),
        source_endpoint = endpoint_text(pinfo.src, pinfo.src_port),
        destination_endpoint = endpoint_text(pinfo.dst, pinfo.dst_port),
        subject_id_modulus = UDP_SUBJECT_ID_MODULUS,
        gossip_first = UDP_SUBJECT_ID_GOSSIP_FIRST,
        gossip_count = UDP_SUBJECT_ID_GOSSIP_COUNT,
        gossip_digits = 4,
        broadcast_subject_id = UDP_SUBJECT_ID_BROADCAST,
        service = false,
        session = true,
        errors = {},
    }
    meta.header_crc_good = meta.header_crc == meta.header_crc_calculated
    local destination_ip = ipv4_number(pinfo.dst)
    if destination_ip ~= nil and (destination_ip & 0xFF800000) == 0xEF000000 then
        meta.subject_id = destination_ip & UDP_SUBJECT_ID_BROADCAST
        meta.scope = scope_for(meta)
    else
        meta.scope = "unicast"
    end
    local payload_end = meta.frame_offset + #meta.frame_payload
    meta.sot = meta.frame_offset == 0
    meta.eot = payload_end == meta.transfer_payload_size
    meta.valid = true
    if meta.version ~= UDP_HEADER_VERSION then
        meta.errors[#meta.errors + 1] = { "incompatible", "Unsupported Cyphal/UDP header version" }
        meta.valid = false
    end
    if meta.incompatibility ~= 0 then
        meta.errors[#meta.errors + 1] = { "incompatible", "Cyphal/UDP incompatibility bits are nonzero" }
        meta.valid = false
    end
    if meta.void ~= 0 then
        meta.errors[#meta.errors + 1] = { "noncanonical", "Cyphal/UDP void bits are nonzero" }
    end
    if not meta.header_crc_good then
        meta.errors[#meta.errors + 1] = { "header_crc", "Cyphal/UDP header CRC-32C mismatch" }
        meta.valid = false
    end
    if payload_end > meta.transfer_payload_size then
        meta.errors[#meta.errors + 1] = { "malformed", "Frame payload extends beyond the advertised transfer size" }
        meta.valid = false
    end
    if meta.transfer_payload_size > cyphal_udp.prefs.max_reassembly_bytes then
        meta.errors[#meta.errors + 1] = { "reassembly", "Transfer exceeds the configured reassembly limit" }
        meta.valid = false
    end
    if meta.scope ~= "unicast" and tonumber(pinfo.dst_port) ~= UDP_PORT then
        meta.errors[#meta.errors + 1] = { "malformed", "Multicast Cyphal/UDP traffic must use destination port 9382" }
        meta.valid = false
    end
    return meta
end

local function render_udp_header(root, tvb, meta)
    root:add(uf.version, tvb(0, 1))
    root:add(uf.priority, tvb(0, 1))
    root:add(uf.void, tvb(1, 1))
    root:add(uf.incompatibility, tvb(1, 1))
    root:add_le(uf.transfer_id, tvb(2, 6))
    root:add_le(uf.sender_uid, tvb(8, 8))
    root:add_le(uf.frame_offset, tvb(16, 4))
    root:add_le(uf.transfer_size, tvb(20, 4))
    root:add_le(uf.prefix_crc, tvb(24, 4))
    root:add_le(uf.header_crc, tvb(28, 4))
    add_generated(root, uf.header_crc_calculated, meta.header_crc_calculated)
    add_generated(root, uf.header_crc_good, meta.header_crc_good)
    add_generated(root, uf.scope, meta.scope)
    add_generated(root, uf.source_endpoint, meta.source_endpoint)
    add_generated(root, uf.destination_endpoint, meta.destination_endpoint)
    add_generated(root, uf.logical_source, u64_hex(meta.sender_uid))
    add_generated(root, uf.sot, meta.sot)
    add_generated(root, uf.eot, meta.eot)
    meta.session_color = udp_color_slot(meta)
    add_generated(root, uf.session_color, meta.session_color)
    if meta.subject_id ~= nil then add_generated(root, uf.subject_id, meta.subject_id) end
    if #meta.frame_payload > 0 then root:add(uf.frame_payload, tvb(UDP_HEADER_SIZE, #meta.frame_payload)) end
    for _, issue in ipairs(meta.errors) do
        add_expert(root, udp_transport_experts[issue[1]], tvb(), issue[2])
    end
end

local function add_udp_logical_destination(root, meta, name)
    local value = meta.destination_endpoint
    if meta.scope ~= "unicast" then
        value = (meta.scope == "multicast" and name ~= nil) and named_topic_destination(meta, name)
            or destination_text(meta)
    end
    add_generated(root, uf.logical_destination, value)
end

local function udp_generic_info(meta)
    return string.format("UDP1.1 prio=%d tid=%d off=%d %d/%d B", meta.priority, meta.transfer_id,
        meta.frame_offset, #meta.frame_payload, meta.transfer_payload_size)
end

local function udp_heuristic_match(tvb)
    if tvb:len() < UDP_HEADER_SIZE then return false end
    local raw = tvb:raw()
    if (string.byte(raw, 1) & 0x1F) ~= UDP_HEADER_VERSION then return false end
    if ((string.byte(raw, 2) >> 5) & 7) ~= 0 then return false end
    if crc32c(raw:sub(1, 28)) ~= u32le(raw, 28) then return false end
    local frame_offset, transfer_size = u32le(raw, 16), u32le(raw, 20)
    return frame_offset + (tvb:len() - UDP_HEADER_SIZE) <= transfer_size
end

local function dissect_udp(tvb, pinfo, tree, heuristic)
    if heuristic and not udp_heuristic_match(tvb) then return false end
    pinfo.cols.protocol = "CYPHAL/UDP"
    local root = tree:add(cyphal_udp, tvb(), "Cyphal/UDP v1.1")
    if tvb:len() < UDP_HEADER_SIZE then
        add_expert(root, udp_ex.malformed, tvb(), "Cyphal/UDP header is shorter than 32 bytes")
        pinfo.cols.info = string.format("⚠️ UDP1.1 short=%d B", tvb:len())
        return not heuristic
    end

    local meta = parse_udp_header(tvb, pinfo)
    pinfo.cols.src = u64_hex(meta.sender_uid)
    pinfo.cols.dst = (meta.scope == "unicast") and meta.destination_endpoint or destination_text(meta)
    render_udp_header(root, tvb, meta)
    if not meta.valid then
        add_udp_logical_destination(root, meta, nil)
        pinfo.cols.info = frame_info(meta, "⚠️ " .. udp_generic_info(meta))
        return true
    end

    local result = process_udp_reassembly(meta, pinfo)
    add_generated(root, uf.duplicate, result.duplicate or false)
    add_generated(root, uf.fragment_count, result.fragment_count or 1)
    if result.reassembled_in ~= nil then add_generated(root, uf.reassembled_in, result.reassembled_in) end
    if result.reassembled_length ~= nil then add_generated(root, uf.reassembled_length, result.reassembled_length) end
    if result.prefix_crc_calculated ~= nil then
        add_generated(root, uf.prefix_crc_calculated, result.prefix_crc_calculated)
        add_generated(root, uf.prefix_crc_good, result.prefix_crc_good)
    end
    for _, issue in ipairs(result.errors) do
        add_expert(root, udp_transport_experts[issue[1]], tvb(), issue[2])
    end

    local name = resolve_topic_name(result.topic_hash)
    add_udp_logical_destination(root, meta, name)
    if meta.scope == "multicast" and name ~= nil then
        pinfo.cols.dst = named_topic_destination(meta, name)
    end
    if result.duplicate then
        pinfo.cols.info = frame_info(result, string.format("🍒 UDP1.1 prio=%d tid=%d off=%d duplicate",
            meta.priority, meta.transfer_id, meta.frame_offset))
        return true
    end
    if not result.complete then
        pinfo.cols.info = frame_info(result, udp_generic_info(meta))
        return true
    end
    if not result.transfer_crc_good then
        if result.payload ~= nil then
            local reassembled = ByteArray.new(result.payload, true):tvb("Invalid reassembled Cyphal/UDP transfer")
            if reassembled:len() > 0 then root:add(uf.payload, reassembled()) end
            retain_udp_result_payload(result)
        end
        pinfo.cols.info = frame_info(result, string.format("⚠️ UDP1.1 prio=%d tid=%d CRC %d B",
            meta.priority, meta.transfer_id, result.reassembled_length or 0))
        return true
    end

    local session_payload = result.payload or result.session_prefix
    if session_payload == nil then
        pinfo.cols.info = frame_info(result, string.format("⚠️ UDP1.1 prio=%d tid=%d cache-miss",
            meta.priority, meta.transfer_id))
        return true
    end
    meta.session_payload_size = result.session_size
    local reassembled = ByteArray.new(session_payload, true):tvb("Reassembled Cyphal/UDP transfer")
    local summary = dissect_session(reassembled, pinfo, root, meta)
    if meta.topic_hash ~= nil then
        result.topic_hash = meta.topic_hash
        for _, frame_number in ipairs(result.frames or {}) do
            local frame_result = udp_frame_results[frame_number]
            if frame_result ~= nil then frame_result.topic_hash = meta.topic_hash end
        end
        local completed = udp_completed_transfers[result.transfer_key]
        if completed ~= nil then completed.topic_hash = meta.topic_hash end
    end
    if result.payload ~= nil then retain_udp_result_payload(result) end
    result.frames = nil
    pinfo.cols.protocol = "CYPHAL1.1"
    pinfo.cols.info = frame_info(result, summary)
    return true
end

function cyphal_can.dissector(tvb, pinfo, tree)
    dissect_can(tvb, pinfo, tree, false)
end

function cyphal_udp.dissector(tvb, pinfo, tree)
    dissect_udp(tvb, pinfo, tree, false)
end

function cyphal_can.init()
    reassembly_sessions = {}
    frame_results = {}
    topic_names = {}
    -- Proto fields are not entered into Wireshark's display-filter registry
    -- until after the Lua script finishes loading. Install the GUI filters here,
    -- once protocol registration is complete, rather than at file scope.
    install_session_colors()
end

function cyphal_udp.init()
    udp_reassembly_sessions = {}
    udp_completed_transfers = {}
    udp_frame_results = {}
    udp_active_transfer_count = 0
    udp_buffered_bytes = 0
    udp_cached_payload_bytes = 0
    udp_payload_cache = {}
    udp_payload_cache_head = 1
    udp_payload_cache_tail = 0
    topic_names = {}
    install_session_colors()
end

cyphal_can:register_heuristic("can", function(tvb, pinfo, tree)
    return dissect_can(tvb, pinfo, tree, true)
end)

cyphal_udp:register_heuristic("udp", function(tvb, pinfo, tree)
    return dissect_udp(tvb, pinfo, tree, true)
end)

local can_table = DissectorTable.get("can.subdissector")
if can_table ~= nil then can_table:add_for_decode_as(cyphal_can) end

local udp_table = DissectorTable.get("udp.port")
if udp_table ~= nil then
    udp_table:add(UDP_PORT, cyphal_udp)
    udp_table:add_for_decode_as(cyphal_udp)
end
