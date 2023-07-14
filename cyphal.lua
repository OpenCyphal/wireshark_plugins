local uavcan_node_heartbeat = require('uavcan_node_heartbeat')

function register_cyphal_messages(cyphal_proto)
    uavcan_node_heartbeat.register(cyphal_proto)
end

function decode_cyphal_messages(payload, pinfo, payload_tree, subject_id)
    if subject_id == uavcan_node_heartbeat.subject_id then
        uavcan_node_heartbeat.decode(payload, pinfo, payload_tree)
    end
end

return {
    register_messages = register_cyphal_messages,
    decode_messages = decode_cyphal_messages,
}