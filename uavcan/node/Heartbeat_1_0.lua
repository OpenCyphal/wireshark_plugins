local PORT_ID = 7509

local uavcan_node_Heartbeat_1_0_uptime = ProtoField.uint32("uavcan.node.Heartbeat_1_0.uptime", "uptime", base.DEC)
local healthTable = {
    [0] = "Nominal",
    [1] = "Advisory",
    [2] = "Caution",
    [3] = "Warning"
}
local uavcan_node_Heartbeat_1_0_health = ProtoField.uint8("uavcan.node.Heartbeat_1_0.health", "health", base.DEC, healthTable)
local modeTable = {
    [0] = "Operational",
    [1] = "Initialization",
    [2] = "Maintenance",
    [3] = "SoftwareUpdate"
}
local uavcan_node_Heartbeat_1_0_mode = ProtoField.uint8("uavcan.node.Heartbeat_1_0.mode", "mode", base.DEC, modeTable)
local uavcan_node_Heartbeat_1_0_vssc = ProtoField.uint8("uavcan.node.Heartbeat_1_0.vssc", "vssc", base.HEX)

-- local flag to prevent multiple inclusion
local uavcan_node_Heartbeat_1_0_registered = false

-- Registers the fields of the {{message}} to the Proto
--@param cyphal_proto The Proto to add the fields to
function register_uavcan_node_Heartbeat_1_0(cyphal_proto)
    if not uavcan_node_Heartbeat_1_0_registered then
        table.insert(cyphal_proto.fields, uavcan_node_Heartbeat_1_0_uptime)
        table.insert(cyphal_proto.fields, uavcan_node_Heartbeat_1_0_health)
        table.insert(cyphal_proto.fields, uavcan_node_Heartbeat_1_0_mode)
        table.insert(cyphal_proto.fields, uavcan_node_Heartbeat_1_0_vssc)
        uavcan_node_Heartbeat_1_0_registered = true
    end
end

function decode_uavcan_node_Heartbeat_1_0(proto, payload, pinfo, payload_tree)
    local offset = 0
    payload_tree:add_le(uavcan_node_Heartbeat_1_0_uptime, payload(offset, 4))
    offset = offset + 4
    payload_tree:add(uavcan_node_Heartbeat_1_0_health, payload(offset, 1))
    offset = offset + 1
    payload_tree:add(uavcan_node_Heartbeat_1_0_mode, payload(offset, 1))
    offset = offset + 1
    payload_tree:add(uavcan_node_Heartbeat_1_0_vssc, payload(offset, 1))
    offset = offset + 1
    return offset
end

return {
    register = register_uavcan_node_Heartbeat_1_0,
    decode = decode_uavcan_node_Heartbeat_1_0,
    subject_id = PORT_ID
}
