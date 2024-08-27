-- constants
local BIT_EXTENT = 1024
local EXTENT = BIT_EXTENT / 8
local BIT_CAPACITY = 512
local CAPACITY = BIT_CAPACITY / 8

-- constituent field
local uavcan_node_port_ServiceIDList_1_0_len = ProtoField.uint8('uavcan.node.port.ServiceIDList_1_0._len_', '_len_', base.DEC)

local uavcan_node_port_ServiceID_1_0 = require('ServiceID_1_0')

-- local flag to prevent multiple inclusion
local uavcan_node_port_ServiceIDList_1_0_registered = false

-- Registers the fields of the message to the Proto
-- @param cyphal_proto The Proto to add the fields to
local function register_uavcan_node_port_ServiceIDList_1_0(cyphal_proto)
    if not uavcan_node_port_ServiceIDList_1_0_registered then
        table.insert(cyphal_proto.fields, uavcan_node_port_ServiceIDList_1_0_tag)
        table.insert(cyphal_proto.fields, uavcan_node_port_ServiceIDList_1_0_len)
        uavcan_node_port_ServiceID_1_0.register(cyphal_proto)
        uavcan_node_port_ServiceIDList_1_0_registered = true
    end
end

local function uint16_to_bytes_le(value)
    local arr = ByteArray.new("0000")
    arr:set_index(0, bit.band(value, 0xFF))     -- low byte
    arr:set_index(1, bit.rshift(value, 8))      -- high byte
    return arr
end

local function decode_uavcan_node_port_ServiceIDList_1_0(proto, payload, pinfo, payload_tree)
    local offset = 0
    -- bit array
    local mask = payload(offset, CAPACITY):bytes()
    offset = offset + CAPACITY
    for i = 1, CAPACITY do
        for j = 1, 8 do
            local t = bit.lshift(1, j - 1)
            local m = bit.band(mask:get_index(i-1), t)
            local b = bit.rshift(m, j - 1)
            if b == 1 then
                local id = (8 * (i - 1)) + (j - 1)
                local buffer = uint16_to_bytes_le(id):tvb()
                uavcan_node_port_ServiceID_1_0.decode(proto, buffer, pinfo, payload_tree)
            end
        end
    end
    return offset
end

return {
    register = register_uavcan_node_port_ServiceIDList_1_0
    , decode = decode_uavcan_node_port_ServiceIDList_1_0
    , extent = EXTENT
}