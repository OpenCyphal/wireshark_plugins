--                            ____                   ______            __          __
--                           / __ `____  ___  ____  / ____/_  ______  / /_  ____  / /
--                          / / / / __ `/ _ `/ __ `/ /   / / / / __ `/ __ `/ __ `/ /
--                         / /_/ / /_/ /  __/ / / / /___/ /_/ / /_/ / / / / /_/ / /
--                         `____/ .___/`___/_/ /_/`____/`__, / .___/_/ /_/`__,_/_/
--                             /_/                     /____/_/
--
-- Wireshark Lua dissector for Cyphal heartbeats, transport-agnostic.
-- Copyright (c) Pavel Kirienko <pavel@opencyphal.org>

--[[
# Cyphal v1.1 heartbeat definition (adds extra fields on top of v1.0 and is backward-compatible):
uint32 uptime               # [second]
uint24 user_word            # In v1.0 this is (health, mode, vendor-specific status); now opaque application-defined.
# End of v1.0 fields, the rest is v1.1-specific.
uint8 version               # =1 for v1.1; reads as 0 in v1.0 due to the implicit zero extension.
uint64 topic_hash
uint40 topic_evictions
int8 topic_log_age          # floor(log2(topic_age)); -1 for zero-age topics.
void8
utf8[<=TOPIC_NAME_MAX] topic_name
--]]

local heartbeat_proto              = Proto("cyphal_heartbeat", "Cyphal Heartbeat")

local f_uptime                     = ProtoField.uint32("heartbeat.uptime", "Uptime [s]", base.DEC, nil, nil, "[second]")
local f_user                       = ProtoField.uint24("heartbeat.user_word", "User word", base.HEX, nil, nil,
    "Formerly 3 separate fields: health, mode, vendor-specific status; now all 24 bits are opaque application-defined")
local f_user_0                     = ProtoField.uint8("heartbeat.user_word.byte0", "v1.0 health", base.DEC)
local f_user_1                     = ProtoField.uint8("heartbeat.user_word.byte1", "v1.0 mode", base.DEC)
local f_user_2                     = ProtoField.uint8("heartbeat.user_word.byte2", "v1.0 vendor-specific status",
    base.DEC)

local f_version                    = ProtoField.uint8("heartbeat.version", "Version", base.DEC)
local f_topic_hash                 = ProtoField.uint64("heartbeat.topic_hash", "Topic hash", base.HEX)
local f_topic_evictions            = ProtoField.uint64("heartbeat.topic_evictions", "Topic evictions", base.DEC)
local f_topic_lage                 = ProtoField.int8("heartbeat.topic_lage", "Topic age floor∘log", base.DEC)
local f_topic_name_len             = ProtoField.uint8("heartbeat.topic_name_len", "Topic name length", base.DEC)
local f_topic_name                 = ProtoField.string("heartbeat.topic_name", "Topic name", base.ASCII)

-- Computed synthetic fields
local f_syn_topic_subject_id_16bit = ProtoField.uint16("heartbeat.topic_subject_id_16bit", "Subject-ID 16b", base.HEX)
local f_syn_topic_subject_id_23bit = ProtoField.uint24("heartbeat.topic_subject_id_23bit", "Subject-ID 23b", base.HEX)
local f_syn_topic_age_bracket      = ProtoField.string("heartbeat.topic_age_bracket", "Topic age bracket", base.ASCII)

heartbeat_proto.fields             = {
    f_uptime,
    f_user,
    f_user_0,
    f_user_1,
    f_user_2,
    f_version,
    f_topic_hash,
    f_topic_evictions,
    f_topic_lage,
    f_topic_name_len,
    f_topic_name,
    -- synthetic
    f_syn_topic_subject_id_16bit,
    f_syn_topic_subject_id_23bit,
    f_syn_topic_age_bracket
}

function heartbeat_proto.dissector(tvb, pinfo, tree)
    if tvb:len() < 7 then
        return
    end
    pinfo.cols.protocol = "CYPHAL❤"
    local subtree = tree:add(heartbeat_proto, tvb(), "Cyphal Heartbeat")
    local offset = 0

    -- uptime
    subtree:add_le(f_uptime, tvb(offset, 4))
    local uptime = tvb(offset, 4):le_uint()
    offset = offset + 4

    -- user word
    local user_tree = subtree:add_le(f_user, tvb(offset, 3))
    local user_word_val = tvb(offset, 3):le_uint()
    user_tree:add_le(f_user_0, tvb(offset, 1))
    user_tree:add_le(f_user_1, tvb(offset + 1, 1))
    user_tree:add_le(f_user_2, tvb(offset + 2, 1))
    offset = offset + 3

    -- Default Info column
    local info = string.format("⏳% 6us 👤%06x", uptime, user_word_val)
    pinfo.cols.info = info

    -- heartbeat version
    if tvb:len() <= offset + 4 then
        return -- Cyphal v1.0 heartbeat, no further fields
    end
    local hb_version = tvb(offset, 1):le_uint()
    subtree:add(f_version, tvb(offset, 1))
    offset = offset + 1

    -- Version-specific parts
    if hb_version ~= 1 then
        return
    end
    if tvb:len() < offset + 16 then -- Check if the fixed-length part is fully present
        return
    end

    -- topic hash
    local topic_hash = tvb(offset, 8):le_uint64():tonumber()
    local topic_hash_lo = tvb(offset + 0, 4):le_uint()
    local topic_hash_hi = tvb(offset + 4, 4):le_uint()
    subtree:add_le(f_topic_hash, tvb(offset, 8))
    offset = offset + 8

    -- topic evictions
    subtree:add_le(f_topic_evictions, tvb(offset, 5))
    local topic_evictions = tvb(offset, 5):le_uint64():tonumber()
    offset = offset + 5

    -- floor(log(topic_age))
    local lage_range = tvb(offset, 1)
    local topic_lage = lage_range:int()
    subtree:add(f_topic_lage, lage_range)
    offset = offset + 1

    -- reserved
    offset = offset + 1

    -- topic name
    local name_len_range = tvb(offset, 1)
    local name_len = name_len_range:uint()
    subtree:add(f_topic_name_len, name_len_range)
    offset = offset + 1
    local remaining = tvb:len() - offset
    local actual_len = name_len
    if actual_len > remaining then
        actual_len = remaining
    end
    local topic_name = ""
    if actual_len > 0 then
        local name_range = tvb(offset, actual_len)
        topic_name = name_range:string()
        subtree:add(f_topic_name, name_range, topic_name)
    end

    -- Computed synthetic field: subject-ID
    subtree:add(f_syn_topic_subject_id_16bit, topic_subject_id(topic_hash, topic_evictions, 57349)):set_generated()
    subtree:add(f_syn_topic_subject_id_23bit, topic_subject_id(topic_hash, topic_evictions, 8380417)):set_generated()

    -- Computed synthetic field: topic age range
    local topic_age_bracket = "[0…1)s";
    if topic_lage >= 0 then
        topic_age_bracket = string.format("[%u…%u)s", 2 ^ topic_lage, 2 ^ (topic_lage + 1))
    end
    subtree:add(f_syn_topic_age_bracket, topic_age_bracket):set_generated()

    -- Update Info column
    pinfo.cols.info = info .. string.format(
        " 📢 ev=%u lage=%+03d 0x%08x%08x '%s'",
        topic_evictions, topic_lage, topic_hash_hi, topic_hash_lo, topic_name
    )
end

-- https://github.com/OpenCyphal-Garage/cy/issues/12
function topic_subject_id(hash, evictions, modulus)
    return 8186 + (hash + evictions * evictions) % modulus
end

-- Register dissector for Cyphal Heartbeat subject-ID.
-- It is essential that the Cyphal transport dissector is registered before this, which we ensure by naming
-- higher-level dissectors such that they compare lexicographically greater than the transport dissectors.
local cyphal_subject_table = DissectorTable.get("cyphal.subject_id")
cyphal_subject_table:add(7509, heartbeat_proto)
