-- Wireshark entry: registration, HCI envelope, dispatch, and final diagnostics.
-- Tested with Wireshark 4.4.8 / Lua 5.4.6. The payload layouts are teaching examples, not an actual Samsung specification.
local p = Proto("bthci_vendor.samsung", "Samsung HCI Vendor")
local definitions = require("samsung_fields")
local reader = require("samsung_reader")
local commands = require("samsung_commands")
local events = require("samsung_events")
local command_complete = require("samsung_command_complete")
local f = definitions.fields

p.fields = f
p.experts = definitions.experts

-- Native HCI fields identify the caller; vendor fields keep their own names.
local event_code = Field.new("bthci_evt.code")
local command_opcode = Field.new("bthci_cmd.opcode")

function p.dissector(tvb, pinfo, tree)
    -- HCI headers are included; H4's packet-type byte has already been removed.
    local ev, op = event_code(), command_opcode()
    if not ev and not op then return 0 end
    local root = tree:add(p, tvb())
    local c = reader.new(tvb, root, 0, tvb:reported_len())
    local ok, err = pcall(function()
        local code, opcode
        if ev then
            code = c:take(1, "Event Code"):uint()
            local length = c:take(1, "Parameter Length"):uint()
            c.limit = 2 + length
        else
            opcode = c:take(2, "Opcode"):le_uint()
            local length = c:take(1, "Parameter Length"):uint()
            c.limit = 3 + length
        end
        if c.limit > tvb:reported_len() then
            c:fail("malformed", "HCI Parameter Length exceeds reported HCI packet length")
        end

        if ev and code == 0xFF then
            local route = c:u(f.subevent_code, 1, "Vendor Subevent")
            local decode = events[route]
            if decode then decode(c) else c:unknown("Unknown vendor subevent") end
        elseif not ev then
            local decode = commands[opcode]
            if decode then decode(c) else c:unknown("Unknown vendor command") end
        elseif code == 0x0E then
            c:take(1, "Num HCI Command Packets")
            opcode = c:take(2, "Completed Opcode"):le_uint()
            local decode = command_complete[opcode]
            if decode then decode(c)
            else c:unknown(string.format("Command Complete 0x%04X: return layout not defined", opcode)) end
        elseif code == 0x0F then
            c:take(4, "Command Status parameters") -- Standard parent displays these fields.
        else
            c:unknown("Unsupported HCI event")
        end

        c:finish() -- Top-level exact-consumption rule, matching SG policy.
        if c.limit < tvb:reported_len() then
            c:fail("malformed", "Bytes exist after declared HCI parameter area")
        end
    end)
    if not ok then
        if reader.is_input_error(err) then
            err.tree:add_proto_expert_info(err.expert, err.text)
        else
            error(err, 0) -- Do not disguise programming errors as malformed input.
        end
    end
    pinfo.cols.info:append(" [SAMSUNG]")
    return tvb:captured_len()
end

-- FT_NONE: select the protocol through Decode As, not add(0xFC01, p).
DissectorTable.get("bthci_cmd.vendor"):add_for_decode_as(p)
return p
