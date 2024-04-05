-- Cyphal/UDP Wireshark Plugin which supports only the Cyphal/UDP Header
local cyphal_udp_info =
{
   version = "1.0 beta",
   author = "Erik Rainey",
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
    return bit.bnot(crc)
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
local CYPHAL_UDP_PORT = 9382 -- The port number used by Cyphal/UDP
local CYPHAL_UDP_HEADER_SIZE = 24 -- The sizeof the Cyphal/UDP Header
local ANONYMOUS_UDP_NODE_ID = 65535 -- The Anonymous Node ID in Cyphal/UDP (not the same as in CAN!)
-- Custom protocol dissector
local cyphal_udp = Proto("cyphaludp", "Cyphal/UDP Protocol 1.0 beta")

ipv4_src = ProtoField.ipv4("cyphal_udp.ip_src", "Source IPv4 Address")
ipv4_dst = ProtoField.ipv4("cyphal_udp.ip_dst", "Destination IPv4 Address")
ipv4_snm = ProtoField.bool("cyphal_udp.ip_service_not_message", "ip_service_not_message", base.NONE)
version = ProtoField.uint8("cyphal_udp.version", "version", base.DEC)
priority =ProtoField.uint8("cyphal_udp.priority", "priority", base.DEC)
source_node_id = ProtoField.uint16("cyphal_udp.source_node_id", "source_node_id", base.DEC)
destination_node_id = ProtoField.uint16("cyphal_udp.destination_node_id", "destination_node_id", base.DEC)
data_specifier = ProtoField.uint16("cyphal_udp.data_specifier", "data_specifier", base.DEC)
service_not_message = ProtoField.bool("cyphal_udp.service_not_message", "service_not_message", base.NONE)
subject_id = ProtoField.uint16("cyphal_udp.subject_id", "subject_id", base.DEC)
service_id = ProtoField.uint16("cyphal_udp.service_id", "service_id", base.DEC)
request_not_response = ProtoField.bool("cyphal_udp.request_not_response", "request_not_response", base.NONE)
transfer_id = ProtoField.uint64("cyphal_udp.transfer_id", "transfer_id", base.DEC)
frame_index_eot = ProtoField.uint32("cyphal_udp.frame_index_eot", "frame_index_eot", base.HEX)
frame_index = ProtoField.uint32("cyphal_udp.frame_index", "frame_index", base.DEC)
end_of_transfer = ProtoField.bool("cyphal_udp.end_of_transfer", "end_of_transfer", base.NONE)
user_data = ProtoField.uint16("cyphal_udp.user_data", "user_data", base.HEX)
crc16_ccitt_false = ProtoField.uint16("cyphal_udp.crc16_ccitt_false", "CRC16-CCITT-FALSE (BE)", base.HEX)
computed_crc16_ccitt_false = ProtoField.uint16("cyphal_udp.computed_crc16_ccitt_false", "CRC16-CCITT-FALSE [Computed]", base.HEX)
serialized_payload = ProtoField.bytes("cyphal_udp.serialized_payload", "serialized_payload", base.SPACE)
serialized_payload_size = ProtoField.uint32("cyphal_udp.serialized_payload_size", "serialized_payload_size", base.DEC)
computed_crc32 = ProtoField.uint32("cyphal_udp.computed_crc32", "CRC32-C [Computed]", base.HEX)
crc32 = ProtoField.uint32("cyphal_udp.crc32", "CRC32-C (LE)", base.HEX)

-- Protocol fields
cyphal_udp.fields = {
    ipv4_src, ipv4_dst, ipv4_snm,
    version, priority,
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
    serialized_payload,
    serialized_payload_size,
    computed_crc32,
    crc32
    -- Add more fields as needed
}

crc16_mismatch_expert = ProtoExpert.new("cyphal_udp.crc16_match", "crc16_match", expert.group.CHECKSUM, expert.severity.WARN)
crc32_mismatch_expert = ProtoExpert.new("cyphal_udp.crc32_match", "crc32_match", expert.group.CHECKSUM, expert.severity.WARN)

cyphal_udp.experts = {
    crc16_mismatch_expert, crc32_mismatch_export
}

ipv4_source_address_field = Field.new("ip.src")
ipv4_destination_address_field = Field.new("ip.dst")

-- Function to dissect the custom protocol
local function dissect_cyphal_udp(buffer, pinfo, tree)
    -- Create a subtree for the custom protocol
    local metadata_tree = tree:add(cyphal_udp, buffer(), "Cyphal/UDP Metadata")
    local header_tree = tree:add(cyphal_udp, buffer(), "Cyphal/UDP Header")
    local payload_tree = tree:add(cyphal_udp, buffer(), "Cyphal/UDP Payload")
    local footer_tree = tree:add(cyphal_udp, buffer(), "Cyphal/UDP Footer")

    if (ipv4_source_address_field()) then
        local ip_src = ipv4_source_address_field().value
        metadata_tree:add(ipv4_src, ip_src)
    end
    if (ipv4_destination_address_field()) then
        local ip_dst = ipv4_destination_address_field().value
        metadata_tree:add(ipv4_dst, ip_dst)
    end

    -- Add fields to the subtree
    header_tree:add_le(version, buffer(0, 1))
    header_tree:add_le(priority, buffer(1, 1))
    header_tree:add_le(source_node_id, buffer(2, 2))
    local dst_node_id = buffer(4, 2):le_uint()
    if dst_node_id == ANONYMOUS_UDP_NODE_ID then
        header_tree:add_expert_info(PI_PROTOCOL, PI_NOTE, "Anonymous/Broadcast Destintation Node ID")
    else
        header_tree:add_le(destination_node_id, buffer(4, 2))
    end
    local ds = buffer(6, 2):le_uint()
    local port_id = bit.band(ds, 0x7FFF)
    local snm = bit.rshift(bit.band(ds, 0x8000), 15)
    local rnr = false
    if snm == 1 then
        if port_id > 16384 then
            port_id = port_id - 16384
            rnr = true
        end
        header_tree:add_le(request_not_response, rnr)
        header_tree:add_le(service_id, port_id)
    else
        header_tree:add_le(subject_id, port_id)
    end
    header_tree:add_le(service_not_message, snm)
    header_tree:add_le(data_specifier, buffer(6, 2))
    header_tree:add_le(transfer_id, buffer(8, 8))
    header_tree:add_le(frame_index_eot, buffer(16, 4))
    local fi = buffer(16, 4):le_uint()
    local fidx = bit.band(fi, 0x7FFFFFFF)
    local eot = bit.rshift(bit.band(fi, 0x80000000), 31)
    header_tree:add_le(frame_index, fidx)
    header_tree:add_le(end_of_transfer, eot)
    header_tree:add_le(user_data, buffer(20, 2))
    local header = buffer(0, CYPHAL_UDP_HEADER_SIZE-2):bytes()
    local captured_crc16 = buffer(CYPHAL_UDP_HEADER_SIZE-2, 2)
    header_tree:add(crc16_ccitt_false, captured_crc16)
    local computed_crc16 = crc16_ccitt(header)
    header_tree:add(computed_crc16_ccitt_false, computed_crc16)
    -- process the number as BE
    if not captured_crc16 == computed_crc16 then
        header_tree:add_expert_info(PI_CHECKSUM, PI_WARN, "CRC16 Mismatch")
    end
    local len = buffer:len()
    local crc_size = 0
    if eot == 1 then
        crc_size = 4
    end
    local rem = len - CYPHAL_UDP_HEADER_SIZE - crc_size -- the remaining bytes minus CRC32C (if EOT)
    if rem > 0 then
        payload_tree:add_le(serialized_payload_size, rem)
        payload_tree:add_le(serialized_payload, buffer(CYPHAL_UDP_HEADER_SIZE, rem))
    end
    if eot == 1 then
        local captured_crc32 = buffer(len-crc_size, 4)
        footer_tree:add_le(crc32, captured_crc32)
        if fidx == 0 then -- We can only compute over 1 frame for now
            local payload = buffer(CYPHAL_UDP_HEADER_SIZE, rem):bytes()
            local crc32_local = crc32c_calc(payload)
            footer_tree:add(computed_crc32, crc32_local)
            if not crc32_local == captured_crc32 then 
                footer_tree:add_expert_info(PI_CHECKSUM, PI_WARN, "CRC32 Mismatch")
            end
        end
    end
    -- Add more field dissectors as needed
end

-- UDP dissector
local udp_dissector = Dissector.get("udp")

-- Register the custom protocol dissector
function cyphal_udp.dissector(buffer, pinfo, tree)
    local src_port = pinfo.src_port
    local dst_port = pinfo.dst_port

    -- Check if the UDP packet uses the custom protocol port
    if src_port == CYPHAL_UDP_PORT or dst_port == CYPHAL_UDP_PORT then
        local subtree = tree:add(cyphal_udp, buffer(), "Cyphal/UDP Protocol Data")
        pinfo.cols.protocol = cyphal_udp.name
        -- Call the custom protocol dissector
        dissect_cyphal_udp(buffer, pinfo, subtree)
    else
        -- Call the default UDP dissector for other ports
        udp_dissector:call(buffer, pinfo, tree)
    end
end

-- Register the custom protocol
local udp_port_table = DissectorTable.get("udp.port")
udp_port_table:add(CYPHAL_UDP_PORT, cyphal_udp)
