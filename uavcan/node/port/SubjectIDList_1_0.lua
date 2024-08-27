local nunavut_support = require('nunavut_support')

-- constants
local BIT_EXTENT = 32776
local EXTENT = BIT_EXTENT / 8
local BIT_CAPACITY = 8192
local CAPACITY = BIT_CAPACITY / 8

-- constituent field
local _tags_ = {
    [0] = "BitMask",
    [1] = "SparseList",
    [2] = "Empty"
}
local uavcan_node_port_SubjectIDList_1_0_tag = ProtoField.new('uavcan.node.port.SubjectIDList_1_0._tag_', '_tag_', ftypes.UINT8, _tags_, base.DEC)
local uavcan_node_port_SubjectIDList_1_0_len = ProtoField.uint8('uavcan.node.port.SubjectIDList_1_0._len_', '_len_', base.DEC)

local uavcan_node_port_SubjectID_1_0 = require('SubjectID_1_0')

-- local flag to prevent multiple inclusion
local uavcan_node_port_SubjectIDList_1_0_registered = false

-- Registers the fields of the message to the Proto
-- @param cyphal_proto The Proto to add the fields to
local function register_uavcan_node_port_SubjectIDList_1_0(cyphal_proto)
    if not uavcan_node_port_SubjectIDList_1_0_registered then
        table.insert(cyphal_proto.fields, uavcan_node_port_SubjectIDList_1_0_tag)
        table.insert(cyphal_proto.fields, uavcan_node_port_SubjectIDList_1_0_len)
        uavcan_node_port_SubjectID_1_0.register(cyphal_proto)
        uavcan_node_port_SubjectIDList_1_0_registered = true
    end
end

local function decode_uavcan_node_port_SubjectIDList_1_0(proto, payload, pinfo, payload_tree)
    local offset = 0
    local extent = 0
    if (payload:len() - offset) < EXTENT then
        extent = payload:len() - offset
    else
        extent = EXTENT
    end
    local subtree = payload_tree:add(proto, payload(offset, extent), "uavcan_node_port_SubjectIDList_1_0")
    -- union tag
    local tag = payload(offset, 1):le_uint()
    subtree:add_le(uavcan_node_port_SubjectIDList_1_0_tag, payload(offset, 1))
    offset = offset + 1
    if tag == 0 then
        -- bit array
        local mask = payload(offset, CAPACITY):bytes()
        local functor = function(proto, payload, pinfo, tree, index)
            local buffer = nunavut_support.uint16_to_bytes_le(index):tvb()
            uavcan_node_port_SubjectID_1_0.decode(proto, buffer, pinfo, subtree)
        end
        offset = offset + nunavut_support.as_bool_array(proto, mask, pinfo, subtree, functor)
    elseif tag == 1 then
        -- sparse list
        local elements = payload(offset, 1):le_uint()
        subtree:add_le(uavcan_node_port_SubjectIDList_1_0_len, payload(offset, 1))
        offset = offset + 1
        for i = 1, elements do
            local data = payload(offset, 2)
            uavcan_node_port_SubjectID_1_0.decode(proto, data, pinfo, subtree)
            offset = offset + 2
        end
    elseif tag == 2 then
        -- empty signifying everything is chosen
    end
    return offset
end

return {
    register = register_uavcan_node_port_SubjectIDList_1_0
    , decode = decode_uavcan_node_port_SubjectIDList_1_0
    , extent = EXTENT
}