
-- We store cyphal frames here until we receive the final frame and try to reassembly.
-- This is organized by [source_node_id][destination_node_id][port_id][transfer_id]
-- Services will be in various destination nodes
-- Messages will all be in the Anonymous or Broadcast ID (0) or (0xFFFF)
local frames = {}

-- Conjoins frames into a data structure to hold future transfer
-- @param payload The payload to store
-- @param source_node_id The NODE ID of the sender
-- @param destination_node_id The NODE ID of the receiver or Anonymous/Broadcast
-- @param port_id The subject ID or service ID
-- @param transfer_id The ID that is the same across all frames of a transfer
-- @param frame_index If not nil, allows frames to come out of order
local function add_frame(payload, source_node_id, destination_node_id, port_id, transfer_id, frame_index)
    local snid = source_node_id
    local dnid = destination_node_id
    local pid = port_id
    local tid = transfer_id
    local fid = frame_index or "nil"
    -- print("Adding Frame from ", snid, " to ", dnid, " about ", pid, " number ", tid, " with index ", fid)
    -- create the source node if it doesn't exist
    frames[snid] = frames[snid] or {}
    -- create the destination node if it doesn't exist
    frames[snid][dnid] = frames[snid][dnid] or {}
    -- create the port id if it doesn't exist
    frames[snid][dnid][pid] = frames[snid][dnid][pid] or {}
    -- if the frame index is nil it's for a version which has to be in order on the bus
    if frame_index == nil then
        -- create the transfer ID if it doesn't exist (as a ByteArray)
        frames[snid][dnid][pid][tid] = frames[snid][dnid][pid][tid] or ByteArray.new()
        -- Append the payload to the byte array
        frames[snid][dnid][pid][tid]:append(payload:bytes())
        -- print("Transfer is now ", frames[snid][dnid][pid][tid]:len())
    else
        error("Out of order frames is not supported yet!")
    end
end

--
-- @param source_node_id The NODE ID of the sender
-- @param destination_node_id The NODE ID of the receiver or Anonymous/Broadcast
-- @param port_id The subject ID or service ID
-- @param transfer_id The ID that is the same across all frames of a transfer
local function extract_transfer(source_node_id, destination_node_id, port_id, transfer_id)
    local snid = source_node_id
    local dnid = destination_node_id
    local pid = port_id
    local tid = transfer_id
    -- print("Extracting Frame from ", snid, " to ", dnid, " about ", pid, " number ", tid)
    -- Take everything out and make a copy
    local transfer = frames[snid][dnid][pid][tid]
    -- Delete the entry
    frames[snid][dnid][pid][tid] = nil
    -- return as a tvb
    return transfer:tvb()
end

return {
    add = add_frame
    , extract = extract_transfer
}
