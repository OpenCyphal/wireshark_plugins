-- list all know types
local uavcan_node_Heartbeat_1_0 = require('uavcan.node.Heartbeat_1_0')
local uavcan_node_GetInfo_1_0 = require('uavcan.node.GetInfo_1_0')
local uavcan_node_port_List_1_0 = require('uavcan.node.port.List_1_0')

-- This function registers all known types
local function register_cyphal_types(cyphal_proto)
    uavcan_node_Heartbeat_1_0.register(cyphal_proto)
    uavcan_node_GetInfo_1_0.register(cyphal_proto)
    uavcan_node_port_List_1_0.register(cyphal_proto)
end

-- This function decodes payloads from a type.
local function decode_cyphal_messages(proto, payload, pinfo, payload_tree, subject_id)
    if subject_id == uavcan_node_Heartbeat_1_0.subject_id then
        uavcan_node_Heartbeat_1_0.decode(proto, payload, pinfo, payload_tree, "payload")
    elseif subject_id == uavcan_node_port_List_1_0.subject_id then
        uavcan_node_port_List_1_0.decode(proto, payload, pinfo, payload_tree, "payload")
    else
        payload_tree:add_expert_info(PI_RECEIVE, PI_COMMENT, "Unknown Message type")
    end
end

local function decode_cyphal_services(proto, payload, pinfo, payload_tree, request_not_response, service_id)
    if service_id == uavcan_node_GetInfo_1_0.service_id then
        uavcan_node_GetInfo_1_0.decode(proto, payload, pinfo, payload_tree, request_not_response)
    else
        payload_tree:add_expert_info(PI_RECEIVE, PI_COMMENT, "Unknown Service type")
    end
end

return {
    register_cyphal_types = register_cyphal_types,
    decode_messages = decode_cyphal_messages,
    decode_services = decode_cyphal_services
}