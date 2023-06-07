-- Cyphal/UDP Wireshark Plugin which supports only the Cyphal/UDP Header

-- Protocol constants
local CYPHAL_UDP_PORT = 9382 -- The port number used by Cyphal/UDP
local CYPHAL_UDP_HEADER_SIZE = 24 -- The sizeof the Cyphal/UDP Header
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
serialized_payload = ProtoField.bytes("cyphal_udp.serialized_payload", "serialized_payload", base.SPACE)
serialized_payload_size = ProtoField.uint32("cyphal_udp.serialized_payload_size", "serialized_payload_size", base.DEC)
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
    serialized_payload,
    serialized_payload_size,
    crc32
    -- Add more fields as needed
}

ipv4_source_address_field = Field.new("ip.src")
ipv4_destination_address_field = Field.new("ip.dst")

-- Function to dissect the custom protocol
local function dissect_cyphal_udp(buffer, pinfo, tree)
    -- Create a subtree for the custom protocol
    local cyphal_udp_tree = tree:add(cyphal_udp, buffer(), "Cyphal/UDP Header")

    if (ipv4_source_address_field()) then
        local ip_src = ipv4_source_address_field().value
        cyphal_udp_tree:add(ipv4_src, ip_src)
    end
    if (ipv4_destination_address_field()) then
        local ip_dst = ipv4_destination_address_field().value
        cyphal_udp_tree:add(ipv4_dst, ip_dst)
    end

    -- Add fields to the subtree
    cyphal_udp_tree:add_le(version, buffer(0, 1))
    cyphal_udp_tree:add_le(priority, buffer(1, 1))
    cyphal_udp_tree:add_le(source_node_id, buffer(2, 2))
    cyphal_udp_tree:add_le(destination_node_id, buffer(4, 2))
    local ds = buffer(6, 2):le_uint()
    local port_id = bit.band(ds, 0x7FFF)
    local snm = bit.rshift(bit.band(ds, 0x8000), 15)
    local rnr = false
    if snm == 1 then
        if port_id > 16384 then
            port_id = port_id - 16384
            rnr = true
        end
        cyphal_udp_tree:add_le(request_not_response, rnr)
        cyphal_udp_tree:add_le(service_id, port_id)
    else
        cyphal_udp_tree:add_le(subject_id, port_id)
    end
    cyphal_udp_tree:add_le(service_not_message, snm)
    cyphal_udp_tree:add_le(data_specifier, buffer(6, 2))
    cyphal_udp_tree:add_le(transfer_id, buffer(8, 8))
    -- process the number as BE
    cyphal_udp_tree:add_le(frame_index_eot, buffer(16, 4))
    local fi = buffer(16, 4):le_uint()
    local fidx = bit.band(fi, 0x7FFFFFFF)
    local eot = bit.rshift(bit.band(fi, 0x80000000), 31)
    cyphal_udp_tree:add_le(frame_index, fidx)
    cyphal_udp_tree:add_le(end_of_transfer, eot)
    cyphal_udp_tree:add_le(user_data, buffer(20, 2))
    cyphal_udp_tree:add(crc16_ccitt_false, buffer(22, 2))
    local len = buffer:len()
    local rem = len - CYPHAL_UDP_HEADER_SIZE - 4 -- the remaining bytes minus CRC32C
    if rem > 0 then
        cyphal_udp_tree:add_le(serialized_payload_size, rem)
        cyphal_udp_tree:add_le(serialized_payload, buffer(24, rem))
    end
    cyphal_udp_tree:add_le(crc32, buffer(len-4, 4))
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
