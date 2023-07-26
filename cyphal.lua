local uavcan_node_heartbeat = require('uavcan_node_heartbeat')
local uavcan_node_getinfo = require('uavcan_node_getinfo')

function register_cyphal_types(cyphal_proto)
    uavcan_node_heartbeat.register(cyphal_proto)
    uavcan_node_getinfo.register(cyphal_proto)
end

function decode_cyphal_messages(payload, pinfo, payload_tree, subject_id)
    if subject_id == uavcan_node_heartbeat.subject_id then
        uavcan_node_heartbeat.decode(payload, pinfo, payload_tree)
    end
end

function decode_cyphal_services(payload, pinfo, payload_tree, request_not_response, service_id) 
    if service_id == uavcan_node_getinfo.service_id then
        uavcan_node_getinfo.decode(payload, pinfo, payload_tree, request_not_response)
    end
end

return {
    register_cyphal_types = register_cyphal_types,
    decode_messages = decode_cyphal_messages,
    decode_services = decode_cyphal_services
}