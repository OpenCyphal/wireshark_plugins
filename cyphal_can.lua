-- Cyphal/CAN Wireshark Plugin
local cyphal_can_info =
{
   version = "1.0 beta",
   author = "Erik Rainey",
   description = "Cyphal/CAN Dissector, to be used through Decode As"
}
set_plugin_info(cyphal_can_info)

-- Get the Normal Dissector for CANFD
local can = Dissector.get("can")
local canfd = Dissector.get("canfd")

-- CAN and CAN FD fields we could access, but we'll need to convert into
-- FieldInfo during Dissection.
can_id_field = Field.new("can.id")
can_len_field = Field.new("can.len")
can_rtr = Field.new("can.flags.rtr")
can_xtd = Field.new("can.flags.xtd")
can_fd_brs = Field.new("canfd.flags.brs")

-- Custom protocol dissector
local cyphal_can = Proto("cyphalcan", "Cyphal/CAN Protocol 1.0 Beta")

cyphal_can_id = ProtoField.uint32("cyphal_can.can_id", "can_id", base.HEX)
local priorityTable = {
    [0] = "Exceptional",
    [1] = "Immediate",
    [2] = "Fast",
    [3] = "High",
    [4] = "Nominal",
    [5] = "Low",
    [6] = "Slow",
    [7] = "Optional"
}
cyphal_can_priority = ProtoField.uint32("cyphal_can.priority", "Priority", base.DEC, priorityTable, 0x1C000000, "Priority of the Transfer")
cyphal_can_len = ProtoField.uint8("cyphal_can.payload_length", "Payload Length", base.DEC)
local service_or_messageTable = {
    [0] = "Message Transfer",
    [1] = "Service Transfer"
}
cyphal_can_service_not_message = ProtoField.uint32("cyphal_can.service_not_message", "Message Type", base.DEC, service_or_messageTable, 0x02000000)
local request_or_responseTable = {
    [0] = "Response",
    [1] = "Request"
}
cypahl_can_request_not_response = ProtoField.uint32("cyphal_can.request_not_response", "Service Type", base.DEC, request_or_responseTable, 0x01000000)
local anonymousTable = {
    [0] = "Regular",
    [1] = "Anonymous"
}
cyphal_can_anonymous = ProtoField.uint32("cyphal_can.anonymous", "Transfer Type", base.DEC, anonymousTable, 0x01000000)
cyphal_can_subject_id = ProtoField.uint32("cyphal_can.subject_id", "subject_id", base.DEC, nil, 0x001FFF00)
cyphal_can_service_id = ProtoField.uint32("cyphal_can.service_id", "service_id", base.DEC, nil, 0x007FC000)
cyphal_can_destination_node_id = ProtoField.uint32("cyphal_can.destination_node_id", "destination_node_id", base.DEC, nil, 0x0003F80)
cyphal_can_source_node_id = ProtoField.uint32("cyphal_can.source_node_id", "source_node_id", base.DEC, nil, 0x0000007F)
cyphal_can_start_of_transfer = ProtoField.uint8("cyphal_can.start_of_transfer", "start_of_transfer", base.DEC, nil, 0x80)
cyphal_can_end_of_transfer = ProtoField.uint8("cyphal_can.end_of_transfer", "end_of_transfer", base.DEC, nil, 0x40)
cyphal_can_toggle = ProtoField.uint8("cyphal_can.toggle", "toggle", base.DEC, nil, 0x20)
cyphal_can_transfer_id = ProtoField.uint8("cyphal_can.transfer_id", "transfer_id", base.DEC, nil, 0x1F)
cyphal_can_tail_byte = ProtoField.uint8("cyphal_can.tail_byte", "tail_byte", base.HEX)
cyphal_can_crc = ProtoField.uint16("cyphal_can.crc16", "CRC16/CCITT-FALSE", base.HEX)

cyphal_can.fields = {
    cyphal_can_id,
    cyphal_can_priority,
    cyphal_can_len,
    cyphal_can_service_not_message,
    cypahl_can_request_not_response,
    cyphal_can_anonymous,
    cyphal_can_subject_id,
    cyphal_can_service_id,
    cyphal_can_destination_node_id,
    cyphal_can_source_node_id,
    cyphal_can_tail_byte,
    cyphal_can_start_of_transfer,
    cyphal_can_end_of_transfer,
    cyphal_can_toggle,
    cyphal_can_transfer_id,
    cyphal_can_crc,
    -- Add more fields
}

local cyphal = require('cyphal')
cyphal.register_cyphal_types(cyphal_can)

-- Function to dissect the CYPHAL/CAN
function cyphal_can.dissector(buffer, pinfo, tree)

    -- Extract the alrady found CAN ID
    local can_id_fieldinfo = can_id_field()
    local can_id = can_id_fieldinfo()
    -- SocketCAN converts the DLC to a Length for you
    local can_len_fieldinfo = can_len_field()
    local can_len = can_len_fieldinfo()
    -- we'll dissect the rest too potentially
    local payload_len = buffer:len() - 1
    local payload = buffer(0, payload_len)
    local tail_buffer = buffer(payload_len, 1)

    -- Create a subtree for the custom protocol
    local header_tree = tree:add(cyphal_can, "Cyphal/CAN Header") -- no buffer() since it's over the existing CAN ID
    local payload_tree = tree:add(cyphal_can, payload, "Cyphal/CAN Payload")
    local footer_tree = tree:add(cyphal_can, tail_buffer, "Cyphal/CAN Footer")

    -- common header parts
    header_tree:add(cyphal_can_len, payload_len)
    header_tree:add(cyphal_can_priority, can_id)
    header_tree:add(cyphal_can_service_not_message, can_id)
    -- Tail Byte Decode
    local tail_byte = tail_buffer:uint()
    footer_tree:add(cyphal_can_start_of_transfer, tail_buffer, tail_byte)
    footer_tree:add(cyphal_can_end_of_transfer, tail_buffer, tail_byte)
    footer_tree:add(cyphal_can_toggle, tail_buffer, tail_byte)
    footer_tree:add(cyphal_can_transfer_id, tail_buffer, tail_byte)
    local sot = bit.rshift(bit.band(tail_byte, 0x80), 7)
    local eot = bit.rshift(bit.band(tail_byte, 0x40), 6)
    if sot == 0 and eot == 1 then
      payload_tree:add(cyphal_can_crc, payload(payload_len - 2, 2))
    end
    local snm = bit.band(bit.rshift(can_id, 25), 0x1)
    if (snm == 1) then -- Services
      local rnr = bit.band(bit.rshift(can_id, 24), 0x1)
      header_tree:add(cypahl_can_request_not_response, can_id)
      local r23 = bit.band(bit.rshift(can_id, 23), 0x1)
      if r23 ~= 0 then -- not equal to
          header_tree:add_expert_info(PI_MALFORMED, PI_WARN, "Reserved (23) is incorrect")
      end
      header_tree:add(cyphal_can_service_id, can_id)
      header_tree:add(cyphal_can_destination_node_id, can_id)
      local service_id = bit.band(bit.rshift(can_id, 14), 0x1FF)
      -- Service Decodes based on service_id
      cyphal.decode_services(cyphal_can, payload, pinfo, payload_tree, rnr, service_id)
    else -- Messages
      header_tree:add(cyphal_can_anonymous, can_id)
      local resv = bit.band(bit.rshift(can_id, 21), 0x7)
      if resv ~= 3 then -- not equal to
          header_tree:add_expert_info(PI_MALFORMED, PI_WARN, "Reserved fields(23,22,21) are incorrect")
      end
      header_tree:add(cyphal_can_subject_id, can_id)
      local r4 = bit.band(bit.rshift(can_id, 7), 0x1)
      if r4 ~= 0 then -- not equal to
          header_tree:add_expert_info(PI_MALFORMED, PI_WARN, "Reserved (7) is incorrect")
      end
      local subject_id = bit.band(bit.rshift(can_id, 8), 0x1FFF)
      cyphal.decode_messages(payload, pinfo, payload_tree, subject_id)
    end
    header_tree:add(cyphal_can_source_node_id, can_id)
end

-- To use this, right click on the CANFD message and select Decode As
-- Then subtract the TCP port entry and make a new one which uses the
-- "CAN Next Level Dissector" and set the "current" colums to CYPHALCAN
local can_table = DissectorTable.get("can.subdissector")
can_table:add_for_decode_as(cyphal_can)