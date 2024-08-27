-- constants
local BIT_EXTENT = 16
local EXTENT = BIT_EXTENT / 8
local MAX = 511

-- constituents

-- fields
local uavcan_node_port_ServiceID_1_0 = ProtoField.uint16("uavcan.node.port.ServiceID.1.0", "service_id", base.DEC)

-- local flag to prevent multiple inclusion
local uavcan_node_port_ServiceID_1_0_registered = false

local function register_uavcan_node_port_ServiceID_1_0(cyphal_proto)
    if not uavcan_node_port_ServiceID_1_0_registered then
        table.insert(cyphal_proto.fields, uavcan_node_port_ServiceID_1_0)
        uavcan_node_port_ServiceID_1_0_registered = true
    end
end

local function decode_uavcan_node_port_ServiceID_1_0(proto, payload, pinfo, payload_tree)
    local offset = 0
    payload_tree:add_le(uavcan_node_port_ServiceID_1_0, payload(offset, 2))
    offset = offset + 2
    return offset
end

return {
    register = register_uavcan_node_port_ServiceID_1_0
    , decode = decode_uavcan_node_port_ServiceID_1_0
    , extent = EXTENT
}
