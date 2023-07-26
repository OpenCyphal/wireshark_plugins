
local cyphal_heartbeat_uptime = ProtoField.uint32("uavcan.node.heartbeat.uptime", "uavcan.node.heartbeat.uptime", base.DEC)
local healthTable = {
    [0] = "Nominal",
    [1] = "Advisory",
    [2] = "Caution",
    [3] = "Warning"
}
local cyphal_heartbeat_health = ProtoField.uint8("uavcan.node.heartbeat.health", "uavcan.node.heartbeat.health", base.DEC, healthTable)
local modeTable = {
    [0] = "Operational",
    [1] = "Initialization",
    [2] = "Maintenance",
    [3] = "SoftwareUpdate"
}
local cyphal_heartbeat_mode = ProtoField.uint8("uavcan.node.heartbeat.mode", "uavcan.node.heartbeat.mode", base.DEC, modeTable)
local cyphal_heartbeat_vssc = ProtoField.uint8("uavcan.node.heartbeat.vssc", "uavcan.node.heartbeat.vssc", base.HEX)

-- Registers the fields of the {{message}} to the Proto
--@param cyphal_proto The Proto to add the fields to
function register_uavcan_node_heartbeat(cyphal_proto)
    table.insert(cyphal_proto.fields, cyphal_heartbeat_uptime)
    table.insert(cyphal_proto.fields, cyphal_heartbeat_health)
    table.insert(cyphal_proto.fields, cyphal_heartbeat_mode)
    table.insert(cyphal_proto.fields, cyphal_heartbeat_vssc)
end

function decode_uavcan_node_heartbeat(payload, pinfo, payload_tree)
    payload_tree:add_le(cyphal_heartbeat_uptime, payload(0, 4))
    payload_tree:add(cyphal_heartbeat_health, payload(4, 1))
    payload_tree:add(cyphal_heartbeat_mode, payload(5, 1))
    payload_tree:add(cyphal_heartbeat_vssc, payload(6, 1))
end

return {
    register = register_uavcan_node_heartbeat,
    decode = decode_uavcan_node_heartbeat,
    subject_id = 7509
}

