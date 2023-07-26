
-- GetInfo
local cyphal_getinfo_protocol_version_major = ProtoField.uint8("uavcan.node.getinfo.response.protocol_version.major", "protocol_version.major", base.DEC)
local cyphal_getinfo_protocol_version_minor = ProtoField.uint8("uavcan.node.getinfo.response.protocol_version.minor", "protocol_version.minor", base.DEC)
local cyphal_getinfo_hardware_version_major = ProtoField.uint8("uavcan.node.getinfo.response.hardware_version.major", "hardware_version.major", base.DEC)
local cyphal_getinfo_hardware_version_minor = ProtoField.uint8("uavcan.node.getinfo.response.hardware_version.minor", "hardware_version.minor", base.DEC)
local cyphal_getinfo_software_version_major = ProtoField.uint8("uavcan.node.getinfo.response.software_version.major", "software_version.major", base.DEC)
local cyphal_getinfo_software_version_minor = ProtoField.uint8("uavcan.node.getinfo.response.software_version.minor", "software_version.minor", base.DEC)
local cyphal_getinfo_software_vcs_revision_id = ProtoField.uint64("uavcan.node.getinfo.response.cyphal_getinfo_software_vcs_revision_id", "SW VCS Revision ID", base.HEX)
local cyphal_getinfo_unique_id = ProtoField.bytes("uavcan.node.getinfo.response.unique_id", "Node Unique ID")
local cyphal_getinfo_name = ProtoField.string("uavcan.node.getinfo.response.name", "Node Name")
local cyphal_getinfo_software_image_crc = ProtoField.uint64("uavcan.node.getinfo.response.crc", "CRC-64-WE", base.HEX)
local cyphal_getinfo_certificate_of_authenticity = ProtoField.bytes("uavcan.node.getinfo.response.certificate_of_authenticity", "Certificate of Authenticity")

-- Registers the fields of the {{service}} to the Proto
--@param cyphal_proto The Proto to add the fields to
function register_uavcan_node_getinfo(cyphal_proto)
    table.insert(cyphal_proto.fields, cyphal_getinfo_protocol_version_major)
    table.insert(cyphal_proto.fields, cyphal_getinfo_protocol_version_minor)
    table.insert(cyphal_proto.fields, cyphal_getinfo_hardware_version_major)
    table.insert(cyphal_proto.fields, cyphal_getinfo_hardware_version_minor)
    table.insert(cyphal_proto.fields, cyphal_getinfo_software_version_major)
    table.insert(cyphal_proto.fields, cyphal_getinfo_software_version_minor)
    table.insert(cyphal_proto.fields, cyphal_getinfo_software_vcs_revision_id)
    table.insert(cyphal_proto.fields, cyphal_getinfo_unique_id)
    table.insert(cyphal_proto.fields, cyphal_getinfo_name)
    table.insert(cyphal_proto.fields, cyphal_getinfo_software_image_crc)
    table.insert(cyphal_proto.fields, cyphal_getinfo_certificate_of_authenticity)
end

function decode_uavcan_node_getinfo(payload, pinfo, payload_tree, request_not_response)
    if request_not_response == 1 then -- Request
    else -- Response
        local offset = 0
        payload_tree:add(cyphal_getinfo_protocol_version_major, payload(offset, 1))
        offset = offset + 1
        payload_tree:add(cyphal_getinfo_protocol_version_minor, payload(offset, 1))
        offset = offset + 1
        payload_tree:add(cyphal_getinfo_hardware_version_major, payload(offset, 1))
        offset = offset + 1
        payload_tree:add(cyphal_getinfo_hardware_version_minor, payload(offset, 1))
        offset = offset + 1
        payload_tree:add(cyphal_getinfo_software_version_major, payload(offset, 1))
        offset = offset + 1
        payload_tree:add(cyphal_getinfo_software_version_minor, payload(offset, 1))
        offset = offset + 1
        payload_tree:add(cyphal_getinfo_software_vcs_revision_id, payload(offset, 8))
        offset = offset + 8
        payload_tree:add(cyphal_getinfo_unique_id, payload(offset, 16))
        offset = offset + 16
        local len = payload(offset, 1):uint()
        offset = offset + 1
        payload_tree:add(cyphal_getinfo_name, payload(offset, len))
        offset = offset + len
        len = payload(offset, 1):uint()
        offset = offset + 1
        if len > 0 then
            payload_tree:add(cyphal_getinfo_software_image_crc, payload(offset, len))
        end
        offset = offset + len
        len = payload(offset, 1):uint()
        offset = offset + 1
        if len > 0 then
            payload_tree:add(cyphal_getinfo_certificate_of_authority, payload(offset, len))
        end
    end
end

return {
    register = register_uavcan_node_getinfo,
    decode = decode_uavcan_node_getinfo,
    subject_id = 7509
}

