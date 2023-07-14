-- constants
local PORT_ID = 7510

-- constituent types (observe location in the heirarchy!)
local uavcan_node_port_SubjectIDList_1_0 = require('SubjectIDList_1_0')
local uavcan_node_port_ServiceIDList_1_0 = require('ServiceIDList_1_0')

-- fields which are not types
local uavcan_node_port_List_1_0_delimiter = ProtoField.uint32("uavcan.node.port.List_1_0.delimiter", "_delimiter_")
local uavcan_node_port_List_1_0_publishes = ProtoField.uint16("uavcan.node.port.List_1_0.publishes", "publishes")
local uavcan_node_port_List_1_0_subscribes = ProtoField.uint16("uavcan.node.port.List_1_0.subscribes", "subscribes")
local uavcan_node_port_List_1_0_clients = ProtoField.uint16("uavcan.node.port.List_1_0.clients", "clients")
local uavcan_node_port_List_1_0_servers = ProtoField.uint16("uavcan.node.port.List_1_0.servers", "servers")

-- local flag to prevent multiple inclusion
local uavcan_node_port_List_1_0_registered = false

-- Registers the fields of the message to the Proto
-- @param cyphal_proto The Proto to add the fields to
function register_uavcan_node_port_List_1_0(cyphal_proto)
    if not uavcan_node_port_List_1_0_registered then
        table.insert(cyphal_proto.fields, uavcan_node_port_List_1_0_delimiter)
        table.insert(cyphal_proto.fields, uavcan_node_port_List_1_0_publishes)
        table.insert(cyphal_proto.fields, uavcan_node_port_List_1_0_subscribes)
        table.insert(cyphal_proto.fields, uavcan_node_port_List_1_0_clients)
        table.insert(cyphal_proto.fields, uavcan_node_port_List_1_0_servers)
        -- register subtypes
        uavcan_node_port_SubjectIDList_1_0.register(cyphal_proto)
        uavcan_node_port_ServiceIDList_1_0.register(cyphal_proto)
        uavcan_node_port_List_1_0_registered = true
    end
end

function decode_uavcan_node_port_List_1_0(proto, payload, pinfo, payload_tree)
    local offset = 0
    local delimiter = 0

    -- publishes
    delimiter = payload(offset, 4):le_uint()
    payload_tree:add_le(uavcan_node_port_List_1_0_delimiter, payload(offset, 4))
    offset = offset + 4
    if delimiter > 0 then
        local data = payload(offset, delimiter)
        local publishers = payload_tree:add(proto, data, "Publishers")
        offset = offset + uavcan_node_port_SubjectIDList_1_0.decode(proto, data, pinfo, publishers)
    end
    -- subscribes
    delimiter = payload(offset, 4):le_uint()
    payload_tree:add_le(uavcan_node_port_List_1_0_delimiter, payload(offset, 4))
    offset = offset + 4
    if delimiter > 0 then
        local data = payload(offset, delimiter)
        local subscribes = payload_tree:add(proto, data, "Subscribes")
        offset = offset + uavcan_node_port_SubjectIDList_1_0.decode(proto,  data, pinfo, subscribes)
    end
    -- clients
    delimiter = payload(offset, 4):le_uint()
    payload_tree:add_le(uavcan_node_port_List_1_0_delimiter, payload(offset, 4))
    offset = offset + 4
    if delimiter > 0 then
        local data = payload(offset, delimiter)
        local clients = payload_tree:add(proto, data, "Clients")
        offset = offset + uavcan_node_port_ServiceIDList_1_0.decode(proto,  data, pinfo, clients)
    end
    -- servers
    delimiter = payload(offset, 4):le_uint()
    payload_tree:add_le(uavcan_node_port_List_1_0_delimiter, payload(offset, 4))
    offset = offset + 4
    if delimiter > 0 then
        local data = payload(offset, delimiter)
        local servers = payload_tree:add(proto, data, "Servers")
        offset = offset + uavcan_node_port_ServiceIDList_1_0.decode(proto, data, pinfo, servers)
    end
end

return {
    register = register_uavcan_node_port_List_1_0,
    decode = decode_uavcan_node_port_List_1_0,
    subject_id = PORT_ID
}
