local ebnf = require("lua-ebnf")
local grammarFile = "dsdl.enbf"
local grammarENBF = io.open(grammarfile):read("*a")
-- Generate the grammar from the ENBF
local grammar = enbf.parse(grammarENBF)
-- Generate the parser from the EBNF grammar
local parser = ebnf.generate(grammar)
-- Find all the local .dsdl files and parse them
local dsdl = io.open("434.GetTransportStatistics.0.1.dsdl"):read("*a")
-- Use the parser to match and discover tokens
local tokens = parser:match(dsdl)
-- Print the discovered tokens
for _, token in ipairs(tokens) do
    print(token)
end

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