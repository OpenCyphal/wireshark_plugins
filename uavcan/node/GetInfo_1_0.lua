local PORT_ID = 430
-- GetInfo
local uavcan_node_GetInfo_1_0_protocol_version_major = ProtoField.uint8("uavcan.node.GetInf_1_0.response.protocol_version.major", "protocol_version.major", base.DEC)
local uavcan_node_GetInfo_1_0_protocol_version_minor = ProtoField.uint8("uavcan.node.GetInf_1_0.response.protocol_version.minor", "protocol_version.minor", base.DEC)
local uavcan_node_GetInfo_1_0_hardware_version_major = ProtoField.uint8("uavcan.node.GetInf_1_0.response.hardware_version.major", "hardware_version.major", base.DEC)
local uavcan_node_GetInfo_1_0_hardware_version_minor = ProtoField.uint8("uavcan.node.GetInf_1_0.response.hardware_version.minor", "hardware_version.minor", base.DEC)
local uavcan_node_GetInfo_1_0_software_version_major = ProtoField.uint8("uavcan.node.GetInf_1_0.response.software_version.major", "software_version.major", base.DEC)
local uavcan_node_GetInfo_1_0_software_version_minor = ProtoField.uint8("uavcan.node.GetInf_1_0.response.software_version.minor", "software_version.minor", base.DEC)
local uavcan_node_GetInfo_1_0_software_vcs_revision_id = ProtoField.uint64("uavcan.node.GetInf_1_0.response.uavcan_node_GetInfo_1_0_software_vcs_revision_id", "SW VCS Revision ID", base.HEX)
local uavcan_node_GetInfo_1_0_unique_id = ProtoField.bytes("uavcan.node.GetInf_1_0.response.unique_id", "Node Unique ID")
local uavcan_node_GetInfo_1_0_name = ProtoField.string("uavcan.node.GetInf_1_0.response.name", "Node Name")
local uavcan_node_GetInfo_1_0_software_image_crc = ProtoField.uint64("uavcan.node.GetInf_1_0.response.crc", "CRC-64-WE", base.HEX)
local uavcan_node_GetInfo_1_0_certificate_of_authenticity = ProtoField.bytes("uavcan.node.GetInf_1_0.response.certificate_of_authenticity", "Certificate of Authenticity")

-- local flag to prevent multiple inclusion
local uavcan_node_GetInfo_1_0_registered = false

-- Registers the fields of the {{service}} to the Proto
--@param cyphal_proto The Proto to add the fields to
function register_uavcan_node_GetInfo_1_0(cyphal_proto)
    if not uavcan_node_GetInfo_1_0_registered then
        table.insert(cyphal_proto.fields, uavcan_node_GetInfo_1_0_protocol_version_major)
        table.insert(cyphal_proto.fields, uavcan_node_GetInfo_1_0_protocol_version_minor)
        table.insert(cyphal_proto.fields, uavcan_node_GetInfo_1_0_hardware_version_major)
        table.insert(cyphal_proto.fields, uavcan_node_GetInfo_1_0_hardware_version_minor)
        table.insert(cyphal_proto.fields, uavcan_node_GetInfo_1_0_software_version_major)
        table.insert(cyphal_proto.fields, uavcan_node_GetInfo_1_0_software_version_minor)
        table.insert(cyphal_proto.fields, uavcan_node_GetInfo_1_0_software_vcs_revision_id)
        table.insert(cyphal_proto.fields, uavcan_node_GetInfo_1_0_unique_id)
        table.insert(cyphal_proto.fields, uavcan_node_GetInfo_1_0_name)
        table.insert(cyphal_proto.fields, uavcan_node_GetInfo_1_0_software_image_crc)
        table.insert(cyphal_proto.fields, uavcan_node_GetInfo_1_0_certificate_of_authenticity)
        uavcan_node_GetInfo_1_0_registered = true
    end
end

function decode_uavcan_node_GetInfo_1_0(proto, payload, pinfo, payload_tree, request_not_response)
    local offset = 0
    if request_not_response == 1 then -- Request
    else -- Response
        payload_tree:add(uavcan_node_GetInfo_1_0_protocol_version_major, payload(offset, 1))
        offset = offset + 1
        payload_tree:add(uavcan_node_GetInfo_1_0_protocol_version_minor, payload(offset, 1))
        offset = offset + 1
        payload_tree:add(uavcan_node_GetInfo_1_0_hardware_version_major, payload(offset, 1))
        offset = offset + 1
        payload_tree:add(uavcan_node_GetInfo_1_0_hardware_version_minor, payload(offset, 1))
        offset = offset + 1
        payload_tree:add(uavcan_node_GetInfo_1_0_software_version_major, payload(offset, 1))
        offset = offset + 1
        payload_tree:add(uavcan_node_GetInfo_1_0_software_version_minor, payload(offset, 1))
        offset = offset + 1
        payload_tree:add(uavcan_node_GetInfo_1_0_software_vcs_revision_id, payload(offset, 8))
        offset = offset + 8
        payload_tree:add(uavcan_node_GetInfo_1_0_unique_id, payload(offset, 16))
        offset = offset + 16
        local len = payload(offset, 1):uint()
        offset = offset + 1
        payload_tree:add(uavcan_node_GetInfo_1_0_name, payload(offset, len))
        offset = offset + len
        len = payload(offset, 1):uint()
        offset = offset + 1
        if len > 0 then
            payload_tree:add(uavcan_node_GetInfo_1_0_software_image_crc, payload(offset, len))
        end
        offset = offset + len
        len = payload(offset, 1):uint()
        offset = offset + 1
        if len > 0 then
            payload_tree:add(uavcan_node_GetInfo_1_0_certificate_of_authority, payload(offset, len))
            offset = offset + len
        end
        return offset
    end
end

return {
    register = register_uavcan_node_GetInfo_1_0,
    decode = decode_uavcan_node_GetInfo_1_0,
    service_id = PORT_ID
}

