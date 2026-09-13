-- Ported from BluetoothKit 999c164ab30f2f0fbb15cfe2f5f9a85e38b1bc81:
-- Events/BtStatus/BtStatusDispatch.cs and BtStatusEvents.cs (MIT-licensed source).
-- The .NET Foundation licenses the source files under the MIT license.
-- See docs/SAMSUNG_MIGRATION.md for the source URLs and wire contract.
local f = require("samsung_fields").fields

local function decode_fw_build_id(c)
    local length = c:u(f.fw_build_id_length, 1, "FW Build ID Length")
    local value = c:take(length, "FW Build ID")
    local item = c.tree:add_packet_field(f.fw_build_id, value, ENC_UTF_8)
    -- FT_STRING display can stop at NUL; keep all wire bytes filterable/exportable.
    if length > 0 then item:add(f.fw_build_id_bytes, value) end
end

local tags = {
    [0x0000] = decode_fw_build_id
}

-- The common adapter consumed Event Code, Parameter Length, and Subevent 0x63.
return function(c)
    local tag = c:u(f.bt_status_tag, 2, "BT Status Tag")
    local decode = tags[tag]
    if decode then decode(c)
    else c:unknown(string.format("Unknown BT Status tag 0x%04X", tag)) end
end
