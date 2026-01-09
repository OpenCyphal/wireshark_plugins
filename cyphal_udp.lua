--                            ____                   ______            __          __
--                           / __ `____  ___  ____  / ____/_  ______  / /_  ____  / /
--                          / / / / __ `/ _ `/ __ `/ /   / / / / __ `/ __ `/ __ `/ /
--                         / /_/ / /_/ /  __/ / / / /___/ /_/ / /_/ / / / / /_/ / /
--                         `____/ .___/`___/_/ /_/`____/`__, / .___/_/ /_/`__,_/_/
--                             /_/                     /____/_/
--
-- Cyphal/UDP Wireshark Plugin for Cyphal/UDP v1.0 and v1.1

local cyphal_udp_info =
{
    version = "1.1 dev",
    author = "Erik Rainey and Pavel Kirienko",
    description = "Cyphal/UDP Dissector"
}
set_plugin_info(cyphal_udp_info)

-- CRC32-C table lookup
local crc32c_table = {
    0x00000000, 0xf26b8303, 0xe13b70f7, 0x1350f3f4, 0xc79a971f, 0x35f1141c, 0x26a1e7e8, 0xd4ca64eb,
    0x8ad958cf, 0x78b2dbcc, 0x6be22838, 0x9989ab3b, 0x4d43cfd0, 0xbf284cd3, 0xac78bf27, 0x5e133c24,
    0x105ec76f, 0xe235446c, 0xf165b798, 0x030e349b, 0xd7c45070, 0x25afd373, 0x36ff2087, 0xc494a384,
    0x9a879fa0, 0x68ec1ca3, 0x7bbcef57, 0x89d76c54, 0x5d1d08bf, 0xaf768bbc, 0xbc267848, 0x4e4dfb4b,
    0x20bd8ede, 0xd2d60ddd, 0xc186fe29, 0x33ed7d2a, 0xe72719c1, 0x154c9ac2, 0x061c6936, 0xf477ea35,
    0xaa64d611, 0x580f5512, 0x4b5fa6e6, 0xb93425e5, 0x6dfe410e, 0x9f95c20d, 0x8cc531f9, 0x7eaeb2fa,
    0x30e349b1, 0xc288cab2, 0xd1d83946, 0x23b3ba45, 0xf779deae, 0x05125dad, 0x1642ae59, 0xe4292d5a,
    0xba3a117e, 0x4851927d, 0x5b016189, 0xa96ae28a, 0x7da08661, 0x8fcb0562, 0x9c9bf696, 0x6ef07595,
    0x417b1dbc, 0xb3109ebf, 0xa0406d4b, 0x522bee48, 0x86e18aa3, 0x748a09a0, 0x67dafa54, 0x95b17957,
    0xcba24573, 0x39c9c670, 0x2a993584, 0xd8f2b687, 0x0c38d26c, 0xfe53516f, 0xed03a29b, 0x1f682198,
    0x5125dad3, 0xa34e59d0, 0xb01eaa24, 0x42752927, 0x96bf4dcc, 0x64d4cecf, 0x77843d3b, 0x85efbe38,
    0xdbfc821c, 0x2997011f, 0x3ac7f2eb, 0xc8ac71e8, 0x1c661503, 0xee0d9600, 0xfd5d65f4, 0x0f36e6f7,
    0x61c69362, 0x93ad1061, 0x80fde395, 0x72966096, 0xa65c047d, 0x5437877e, 0x4767748a, 0xb50cf789,
    0xeb1fcbad, 0x197448ae, 0x0a24bb5a, 0xf84f3859, 0x2c855cb2, 0xdeeedfb1, 0xcdbe2c45, 0x3fd5af46,
    0x7198540d, 0x83f3d70e, 0x90a324fa, 0x62c8a7f9, 0xb602c312, 0x44694011, 0x5739b3e5, 0xa55230e6,
    0xfb410cc2, 0x092a8fc1, 0x1a7a7c35, 0xe811ff36, 0x3cdb9bdd, 0xceb018de, 0xdde0eb2a, 0x2f8b6829,
    0x82f63b78, 0x709db87b, 0x63cd4b8f, 0x91a6c88c, 0x456cac67, 0xb7072f64, 0xa457dc90, 0x563c5f93,
    0x082f63b7, 0xfa44e0b4, 0xe9141340, 0x1b7f9043, 0xcfb5f4a8, 0x3dde77ab, 0x2e8e845f, 0xdce5075c,
    0x92a8fc17, 0x60c37f14, 0x73938ce0, 0x81f80fe3, 0x55326b08, 0xa759e80b, 0xb4091bff, 0x466298fc,
    0x1871a4d8, 0xea1a27db, 0xf94ad42f, 0x0b21572c, 0xdfeb33c7, 0x2d80b0c4, 0x3ed04330, 0xccbbc033,
    0xa24bb5a6, 0x502036a5, 0x4370c551, 0xb11b4652, 0x65d122b9, 0x97baa1ba, 0x84ea524e, 0x7681d14d,
    0x2892ed69, 0xdaf96e6a, 0xc9a99d9e, 0x3bc21e9d, 0xef087a76, 0x1d63f975, 0x0e330a81, 0xfc588982,
    0xb21572c9, 0x407ef1ca, 0x532e023e, 0xa145813d, 0x758fe5d6, 0x87e466d5, 0x94b49521, 0x66df1622,
    0x38cc2a06, 0xcaa7a905, 0xd9f75af1, 0x2b9cd9f2, 0xff56bd19, 0x0d3d3e1a, 0x1e6dcdee, 0xec064eed,
    0xc38d26c4, 0x31e6a5c7, 0x22b65633, 0xd0ddd530, 0x0417b1db, 0xf67c32d8, 0xe52cc12c, 0x1747422f,
    0x49547e0b, 0xbb3ffd08, 0xa86f0efc, 0x5a048dff, 0x8ecee914, 0x7ca56a17, 0x6ff599e3, 0x9d9e1ae0,
    0xd3d3e1ab, 0x21b862a8, 0x32e8915c, 0xc083125f, 0x144976b4, 0xe622f5b7, 0xf5720643, 0x07198540,
    0x590ab964, 0xab613a67, 0xb831c993, 0x4a5a4a90, 0x9e902e7b, 0x6cfbad78, 0x7fab5e8c, 0x8dc0dd8f,
    0xe330a81a, 0x115b2b19, 0x020bd8ed, 0xf0605bee, 0x24aa3f05, 0xd6c1bc06, 0xc5914ff2, 0x37faccf1,
    0x69e9f0d5, 0x9b8273d6, 0x88d28022, 0x7ab90321, 0xae7367ca, 0x5c18e4c9, 0x4f48173d, 0xbd23943e,
    0xf36e6f75, 0x0105ec76, 0x12551f82, 0xe03e9c81, 0x34f4f86a, 0xc69f7b69, 0xd5cf889d, 0x27a40b9e,
    0x79b737ba, 0x8bdcb4b9, 0x988c474d, 0x6ae7c44e, 0xbe2da0a5, 0x4c4623a6, 0x5f16d052, 0xad7d5351
}

--- Format a 64-bit little-endian value at the specified offset in the buffer as a 16-digit hex string.
local function hex64(bytes, offset)
    local lo = bytes:get_index(offset + 0) +
        bytes:get_index(offset + 1) * 0x100 +
        bytes:get_index(offset + 2) * 0x10000 +
        bytes:get_index(offset + 3) * 0x1000000
    local hi = bytes:get_index(offset + 4) +
        bytes:get_index(offset + 5) * 0x100 +
        bytes:get_index(offset + 6) * 0x10000 +
        bytes:get_index(offset + 7) * 0x1000000
    return string.format("%08x%08x", hi, lo)
end

--- CRC32-C (Castagnoli)
--- @see https://users.ece.cmu.edu/~koopman/networks/dsn02/dsn02_koopman.pdf
--- @see https://crc32c.machinezoo.com/
local function crc32c_calc(data)
    local crc = 0xFFFFFFFF
    local len = data:len()
    for i = 1, len do
        local index = bit.bxor(bit.band(crc, 0xFF), data:get_index(i - 1))
        crc = bit.bxor(bit.rshift(crc, 8), crc32c_table[index + 1])
    end
    crc = bit.band(bit.bnot(crc), 0xFFFFFFFF)
    if crc < 0 then
        crc = crc + 0x100000000
    end
    return crc
end

--- CRC16-CCITT FALSE function
-- @param str The ByteArray to hash.
-- @return The CRC hash.
local function crc16_ccitt(array)
    local crc = 0xffff -- initial
    local len = array:len()
    local poly = 0x1021
    local check = 0x8000
    for i = 0, len - 1 do
        local c = bit.lshift(array:get_index(i), 8)
        crc = bit.band(bit.bxor(crc, c), 0xFFFF)
        for j = 1, 8 do
            local k = bit.band(crc, check)
            crc = bit.band(bit.lshift(crc, 1), 0xFFFF)
            if k ~= 0 then
                crc = bit.bxor(crc, poly)
            end
        end
    end
    return crc
end

-- Protocol constants
local CYPHAL_UDP_PORT = 9382          -- The port number used by Cyphal/UDP
local CYPHAL_UDP_V10_HEADER_SIZE = 24 -- The sizeof the Cyphal/UDP Header (v1.0)
local CYPHAL_UDP_V11_HEADER_SIZE = 48 -- Size of the Cyphal/UDP Header (v1.1)
local ANONYMOUS_UDP_NODE_ID = 65535   -- The Anonymous Node ID in Cyphal/UDP (not the same as in CAN!)
local PROTOCOL_NAME = "Cyphal/UDP Protocol"

-- Custom protocol dissector
local cyphal_udp = Proto("cyphaludp", PROTOCOL_NAME)

ipv4_snm = ProtoField.bool("cyphal_udp.ip_service_not_message", "ip_service_not_message", base.NONE)
version = ProtoField.uint8("cyphal_udp.version", "version", base.DEC)
priority = ProtoField.uint8("cyphal_udp.priority", "priority", base.DEC)
ack_required = ProtoField.bool("cyphal_udp.ack_required", "ack_required", base.NONE)
source_node_id = ProtoField.uint16("cyphal_udp.source_node_id", "source_node_id", base.DEC)
destination_node_id = ProtoField.uint16("cyphal_udp.destination_node_id", "destination_node_id", base.DEC)
data_specifier = ProtoField.uint16("cyphal_udp.data_specifier", "data_specifier", base.DEC)
service_not_message = ProtoField.bool("cyphal_udp.service_not_message", "service_not_message", base.NONE)
subject_id = ProtoField.uint32("cyphal_udp.subject_id", "subject_id", base.HEX)
service_id = ProtoField.uint16("cyphal_udp.service_id", "service_id", base.HEX)
request_not_response = ProtoField.bool("cyphal_udp.request_not_response", "request_not_response", base.NONE)
transfer_id = ProtoField.uint64("cyphal_udp.transfer_id", "transfer_id", base.HEX)
frame_index_eot = ProtoField.uint32("cyphal_udp.frame_index_eot", "frame_index_eot", base.HEX)
frame_index = ProtoField.uint32("cyphal_udp.frame_index", "frame_index", base.DEC)
end_of_transfer = ProtoField.bool("cyphal_udp.end_of_transfer", "end_of_transfer", base.NONE)
user_data = ProtoField.uint16("cyphal_udp.user_data", "user_data", base.HEX)
crc16_ccitt_false = ProtoField.uint16("cyphal_udp.crc16_ccitt_false", "CRC16-CCITT-FALSE (BE)", base.HEX)
computed_crc16_ccitt_false = ProtoField.uint16("cyphal_udp.computed_crc16_ccitt_false", "CRC16-CCITT-FALSE [Computed]",
    base.HEX)
frame_payload = ProtoField.bytes("cyphal_udp.frame_payload", "frame_payload", base.SPACE)
frame_payload_size = ProtoField.uint32("cyphal_udp.frame_payload_size", "frame_payload_size", base.DEC)
computed_crc32 = ProtoField.uint32("cyphal_udp.computed_crc32", "CRC32-C [Computed]", base.HEX)
crc32 = ProtoField.uint32("cyphal_udp.crc32", "CRC32-C (LE)", base.HEX)
frame_payload_offset = ProtoField.uint32("cyphal_udp.frame_payload_offset", "frame_payload_offset", base.DEC)
transfer_payload_size = ProtoField.uint32("cyphal_udp.transfer_payload_size", "transfer_payload_size", base.DEC)
sender_uid = ProtoField.uint64("cyphal_udp.sender_uid", "sender_uid", base.HEX)
topic_hash = ProtoField.uint64("cyphal_udp.topic_hash", "topic_hash", base.HEX)
prefix_crc32c = ProtoField.uint32("cyphal_udp.prefix_crc32c", "prefix_crc32c", base.HEX)
computed_prefix_crc32c = ProtoField.uint32("cyphal_udp.computed_prefix_crc32c", "prefix_crc32c [Computed]", base.HEX)
header_crc32c = ProtoField.uint32("cyphal_udp.header_crc32c", "header_crc32c", base.HEX)
computed_header_crc32c = ProtoField.uint32("cyphal_udp.computed_header_crc32c", "header_crc32c [Computed]", base.HEX)
local p2p_kind_values = { [0] = "response data", [1] = "ack", }
p2p_kind = ProtoField.uint8("cyphal_udp.p2p_kind", "P2P kind", base.DEC, p2p_kind_values)
p2p_origin_topic_hash = ProtoField.uint64("cyphal_udp.p2p_origin_topic_hash", "P2P origin topic hash", base.HEX)
p2p_origin_transfer_id = ProtoField.uint64("cyphal_udp.p2p_origin_transfer_id", "P2P origin transfer-ID", base.HEX)

-- Protocol fields
cyphal_udp.fields = {
    ipv4_snm,
    version, priority, ack_required,
    source_node_id,
    destination_node_id,
    data_specifier,
    service_not_message,
    subject_id,
    service_id,
    request_not_response,
    transfer_id,
    frame_index_eot,
    frame_index,
    end_of_transfer,
    user_data,
    crc16_ccitt_false,
    computed_crc16_ccitt_false,
    frame_payload,
    frame_payload_size,
    computed_crc32,
    crc32,
    frame_payload_offset,
    transfer_payload_size,
    sender_uid,
    topic_hash,
    prefix_crc32c,
    computed_prefix_crc32c,
    header_crc32c,
    computed_header_crc32c,
    p2p_kind,
    p2p_origin_topic_hash,
    p2p_origin_transfer_id
}

crc16_mismatch_expert = ProtoExpert.new("cyphal_udp.crc16_match", "crc16_match", expert.group.CHECKSUM,
    expert.severity.WARN)
crc32_mismatch_expert = ProtoExpert.new("cyphal_udp.crc32_match", "crc32_match", expert.group.CHECKSUM,
    expert.severity.WARN)

cyphal_udp.experts = {
    crc16_mismatch_expert, crc32_mismatch_expert
}

ipv4_destination_address_field = Field.new("ip.dst")

-- Returns: subject_id (or nil for services), payload_tvb (or nil)
local function dissect_cyphal_udp_v10(buffer, header_tree, payload_tree, footer_tree)
    if buffer:len() < CYPHAL_UDP_V10_HEADER_SIZE then
        header_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Truncated Cyphal/UDP v1.0 header")
        return nil, nil
    end
    header_tree:add_le(version, buffer(0, 1))
    header_tree:add_le(priority, buffer(1, 1))
    header_tree:add_le(source_node_id, buffer(2, 2))
    local dst_node_id = buffer(4, 2):le_uint()
    if dst_node_id == ANONYMOUS_UDP_NODE_ID then
        header_tree:add_expert_info(PI_PROTOCOL, PI_NOTE, "Anonymous/Broadcast Destination Node ID")
    else
        header_tree:add_le(destination_node_id, buffer(4, 2))
    end
    local ds = buffer(6, 2):le_uint()
    local port_id = bit.band(ds, 0x7FFF)
    local snm = bit.rshift(bit.band(ds, 0x8000), 15)
    local rnr = false
    local extracted_subject_id = nil
    if snm == 1 then
        if port_id > 16384 then
            port_id = port_id - 16384
            rnr = true
        end
        header_tree:add(request_not_response, rnr)
        header_tree:add(service_id, port_id)
    else
        header_tree:add(subject_id, port_id)
        extracted_subject_id = port_id
    end
    header_tree:add(service_not_message, snm)
    header_tree:add_le(data_specifier, buffer(6, 2))
    header_tree:add_le(transfer_id, buffer(8, 8))
    header_tree:add_le(frame_index_eot, buffer(16, 4))
    local fi = buffer(16, 4):le_uint()
    local fidx = bit.band(fi, 0x7FFFFFFF)
    local eot = bit.rshift(bit.band(fi, 0x80000000), 31)
    header_tree:add_le(frame_index, fidx)
    header_tree:add_le(end_of_transfer, eot)
    header_tree:add_le(user_data, buffer(20, 2))
    local header = buffer(0, CYPHAL_UDP_V10_HEADER_SIZE - 2):bytes()
    local captured_crc16_range = buffer(CYPHAL_UDP_V10_HEADER_SIZE - 2, 2)
    header_tree:add(crc16_ccitt_false, captured_crc16_range)
    local computed_crc16 = crc16_ccitt(header)
    header_tree:add(computed_crc16_ccitt_false, computed_crc16)
    if captured_crc16_range:uint() ~= computed_crc16 then
        header_tree:add_expert_info(PI_CHECKSUM, PI_WARN, "CRC16 Mismatch")
    end
    local len = buffer:len()
    local crc_size = (eot == 1) and 4 or 0
    local rem = len - CYPHAL_UDP_V10_HEADER_SIZE - crc_size -- the remaining bytes minus CRC32C (if EOT)
    local payload_tvb = nil
    if rem > 0 then
        payload_tree:add_le(frame_payload_size, rem)
        payload_tree:add_le(frame_payload, buffer(CYPHAL_UDP_V10_HEADER_SIZE, rem))
        payload_tvb = buffer(CYPHAL_UDP_V10_HEADER_SIZE, rem):tvb()
    end
    if eot == 1 then
        local captured_crc32_range = buffer(len - crc_size, 4)
        footer_tree:add_le(crc32, captured_crc32_range)
        if fidx == 0 then -- We can only compute over 1 frame for now
            local payload = buffer(CYPHAL_UDP_V10_HEADER_SIZE, rem):bytes()
            local crc32_local = crc32c_calc(payload)
            footer_tree:add(computed_crc32, crc32_local)
            if crc32_local ~= captured_crc32_range:le_uint() then
                footer_tree:add_expert_info(PI_CHECKSUM, PI_WARN, "CRC32 Mismatch")
            end
        end
    end
    return extracted_subject_id, payload_tvb
end

--[[
uint5 version               # =2 for Cyphal v1.1
uint3 priority
bool flag_ack_required
void23
uint24 frame_index
void8
uint32 frame_payload_offset
uint32 transfer_payload_size
uint64 transfer_id
uint64 sender_uid
uint64 topic_hash
uint32 prefix_crc32c        # crc32c(payload[0:(frame_payload_offset+payload_size)])
uint32 header_crc32c
--]]
-- Returns: subject_id (or nil), payload_tvb (or nil)
local function dissect_cyphal_udp_v11(buffer, pinfo, header_tree, payload_tree)
    if buffer:len() < CYPHAL_UDP_V11_HEADER_SIZE then
        header_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Truncated Cyphal/UDP v1.1 header")
        return nil, nil
    end
    local head = buffer(0, 1):uint()
    local version_bits = bit.band(head, 0x1F)
    local priority_bits = bit.band(bit.rshift(head, 5), 0x07)
    local flags = buffer(1, 1):uint()
    local ack_required_val = bit.band(flags, 0x01) ~= 0
    header_tree:add(version, buffer(0, 1), version_bits)
    header_tree:add(priority, buffer(0, 1), priority_bits)
    header_tree:add(ack_required, buffer(1, 1), ack_required_val)
    local fidx = buffer(4, 3):le_uint()
    header_tree:add_le(frame_index, buffer(4, 3), fidx)
    local frame_payload_offset_val = buffer(8, 4):le_uint()
    local transfer_payload_size_val = buffer(12, 4):le_uint()
    header_tree:add_le(frame_payload_offset, buffer(8, 4))
    header_tree:add_le(transfer_payload_size, buffer(12, 4))
    header_tree:add_le(transfer_id, buffer(16, 8))
    header_tree:add_le(sender_uid, buffer(24, 8))
    header_tree:add_le(topic_hash, buffer(32, 8))

    -- Extract the subject-ID from the multicast group address.
    local extracted_subject_id = nil
    local dst_ip = ipv4_destination_address_field()
    if dst_ip then
        local dst_ip_bytes = dst_ip.range:bytes()
        local first_octet = dst_ip_bytes:get_index(0)
        if first_octet >= 224 and first_octet <= 239 then
            local dst_ip_val = dst_ip_bytes:get_index(1) * 0x10000 + dst_ip_bytes:get_index(2) * 0x100 +
                dst_ip_bytes:get_index(3)
            extracted_subject_id = bit.band(dst_ip_val, 0x7FFFFF)
            header_tree:add(subject_id, extracted_subject_id)
        end
    end

    -- Handle the CRCs.
    local prefix_crc_range = buffer(40, 4)
    local header_crc_range = buffer(44, 4)
    header_tree:add_le(prefix_crc32c, prefix_crc_range)
    header_tree:add_le(header_crc32c, header_crc_range)
    local computed_header_crc = crc32c_calc(buffer(0, CYPHAL_UDP_V11_HEADER_SIZE - 4):bytes())
    header_tree:add(computed_header_crc32c, computed_header_crc)
    if computed_header_crc ~= header_crc_range:le_uint() then
        header_tree:add_expert_info(PI_CHECKSUM, PI_WARN, "Header CRC mismatch")
    end
    local len = buffer:len()
    local frame_end = frame_payload_offset_val + len - CYPHAL_UDP_V11_HEADER_SIZE
    if frame_end > transfer_payload_size_val then
        header_tree:add_expert_info(PI_PROTOCOL, PI_WARN, "Frame exceeds declared transfer size")
    end
    if ((fidx == 0) ~= (frame_payload_offset_val == 0)) then
        header_tree:add_expert_info(PI_PROTOCOL, PI_WARN, "First frame flags disagree with payload offset")
    end

    -- For now we only validate the prefix CRC for the first frame only
    if frame_payload_offset_val == 0 then
        local computed_prefix_crc = crc32c_calc(buffer(CYPHAL_UDP_V11_HEADER_SIZE, len - CYPHAL_UDP_V11_HEADER_SIZE):bytes())
        header_tree:add(computed_prefix_crc32c, computed_prefix_crc)
        if computed_prefix_crc ~= prefix_crc_range:le_uint() then
            header_tree:add_expert_info(PI_CHECKSUM, PI_WARN, "Prefix CRC mismatch")
        end
    end

    local payload_len = len - CYPHAL_UDP_V11_HEADER_SIZE
    local payload_offset = CYPHAL_UDP_V11_HEADER_SIZE

    -- Handle P2P traffic. Its payload contains a fixed-size header which we parse here.
    local has_p2p_header = ((extracted_subject_id == nil) and (frame_payload_offset_val == 0) and
        (transfer_payload_size_val >= 24) and (payload_len >= 24))
    local p2p_kind_val = nil
    if has_p2p_header then
        local p2p_offset = CYPHAL_UDP_V11_HEADER_SIZE
        p2p_kind_val = buffer(p2p_offset, 1):uint()
        payload_tree:add_le(p2p_kind, buffer(p2p_offset, 1))
        payload_tree:add_le(p2p_origin_topic_hash, buffer(p2p_offset + 8, 8))
        payload_tree:add_le(p2p_origin_transfer_id, buffer(p2p_offset + 16, 8))
        payload_len = payload_len - 24
        payload_offset = payload_offset + 24
    end

    -- Handle the payload
    local payload_tvb = nil
    if payload_len > 0 then
        payload_tree:add_le(frame_payload_size, payload_len)
        payload_tree:add_le(frame_payload, buffer(payload_offset, payload_len))
        payload_tvb = buffer(payload_offset, payload_len):tvb()
    end

    -- Build the info string
    local header_bytes = buffer(0, CYPHAL_UDP_V11_HEADER_SIZE):bytes()
    local info_prefix
    if extracted_subject_id ~= nil  then info_prefix = "📨"  -- multicast message publication
    elseif p2p_kind_val == 0        then info_prefix = "🔙"  -- p2p response
    elseif p2p_kind_val == 1        then info_prefix = "✔"  -- p2p ack
    else                                 info_prefix = "⁉"  -- unknown
    end
    pinfo.cols.info = string.format(
        "%s %s %s %s #%s [%u:%u)/%u",
        info_prefix,
        hex64(header_bytes, 24), -- source UID
        ack_required_val and "⇉" or "→", -- more arrows indicate ack required (may be retransmissions)
        hex64(header_bytes, 32), -- topic hash
        hex64(header_bytes, 16), -- transfer-ID
        frame_payload_offset_val,
        frame_payload_offset_val + payload_len,
        transfer_payload_size_val
    )
    return extracted_subject_id, payload_tvb
end

local cyphal_subject_table = DissectorTable.new("cyphal.subject_id", "Cyphal Subject-ID", ftypes.UINT32)

local function dissect_cyphal_udp(buffer, pinfo, tree)
    local header_tree = tree:add(cyphal_udp, buffer(), "Cyphal/UDP Header")
    local payload_tree = tree:add(cyphal_udp, buffer(), "Cyphal/UDP Payload")

    local head_byte = (buffer:len() > 0) and buffer(0, 1):uint() or 0
    local version_bits = bit.band(head_byte, 0x1F)
    local subject_id_val, payload_tvb = nil, nil
    if (version_bits == 2) and (buffer:len() >= CYPHAL_UDP_V11_HEADER_SIZE) then
        subject_id_val, payload_tvb = dissect_cyphal_udp_v11(buffer, pinfo, header_tree, payload_tree)
    elseif (version_bits == 1) and (buffer:len() >= CYPHAL_UDP_V10_HEADER_SIZE) then
        local footer_tree = tree:add(cyphal_udp, buffer(), "Cyphal/UDP Footer")
        subject_id_val, payload_tvb = dissect_cyphal_udp_v10(buffer, header_tree, payload_tree, footer_tree)
    else
        header_tree:add_expert_info(PI_PROTOCOL, PI_WARN, "Unsupported Cyphal/UDP version")
    end
    -- Call registered payload dissectors based on subject-ID (only if one is registered)
    if subject_id_val and payload_tvb then
        local subdissector = cyphal_subject_table:get_dissector(subject_id_val)
        if subdissector then
            subdissector:call(payload_tvb, pinfo, tree)
        end
    end
    return buffer:len()
end

local udp_dissector = Dissector.get("udp")

-- Register the custom protocol dissector
function cyphal_udp.dissector(buffer, pinfo, tree)
    if pinfo.dst_port == CYPHAL_UDP_PORT then
        local subtree = tree:add(cyphal_udp, buffer(), PROTOCOL_NAME)
        pinfo.cols.protocol = cyphal_udp.name
        return dissect_cyphal_udp(buffer, pinfo, subtree)
    else
        -- Call the default UDP dissector for other ports
        udp_dissector:call(buffer, pinfo, tree)
        return 0
    end
end

-- Heuristic dissector: checks if a UDP packet is Cyphal/UDP by validating the header CRC.
-- This allows detection of response packets on ephemeral ports (not just port 9382).
local function heuristic_checker(buffer, pinfo, tree)
    if buffer:len() < 1 then
        return false
    end
    local version_bits = bit.band(buffer(0, 1):uint(), 0x1F)  -- First 5 bits contain the version, always.

    -- Try validating the datagram against known protocol versions.
    -- v1.0 does not require heuristic matching because it always uses the constant destination port for all transfers.
    if version_bits == 2 and buffer:len() >= CYPHAL_UDP_V11_HEADER_SIZE then
        local header_crc_range = buffer(44, 4)
        local computed_header_crc = crc32c_calc(buffer(0, CYPHAL_UDP_V11_HEADER_SIZE - 4):bytes())
        if computed_header_crc == header_crc_range:le_uint() then
            local subtree = tree:add(cyphal_udp, buffer(), PROTOCOL_NAME)
            pinfo.cols.protocol = cyphal_udp.name
            dissect_cyphal_udp(buffer, pinfo, subtree)
            return buffer:len()
        end
    end
    return false
end

-- Register heuristic dissector for UDP
cyphal_udp:register_heuristic("udp", heuristic_checker)

-- Register on the well-known port for non-heuristic detection
local udp_port_table = DissectorTable.get("udp.port")
udp_port_table:add(CYPHAL_UDP_PORT, cyphal_udp)
