-- Vendor Event bodies. The HCI header and vendor subevent byte are already read.
-- B0 and A0:0001 mirror SampleVendorContract; all E0 kinds are invented examples.
local f = require("samsung_fields").fields
local reader = require("samsung_reader")
local cursor, bd_addr, rssi, entry = reader.new, reader.bd_addr, reader.rssi, reader.entry
local band, rshift = bit.band, bit.rshift

local function decode_display_types(c) -- Fixed widths, enum, signed value, address, text, computed field.
    c:u(f.status, 1, "Status")
    c:u(f.connection_handle, 2, "Handle")
    c:u(f.lap, 3, "LAP")
    c.tree:add_le(f.counter, c:take(6, "Counter")) -- UInt64 field, six wire bytes.
    bd_addr(c)
    rssi(c)
    local r = c:take(2, "Interval")
    c.tree:add_le(f.slots, r)
    c.tree:add(f.ms, r:le_uint() * 0.625):set_generated()
    c.tree:add(f.ip, c:take(4, "IPv4")) -- Network order.
    local n = c:u(f.length, 1, "Text Length")
    c.tree:add_packet_field(f.text, c:take(n, "Text"), ENC_UTF_8)
end

local function decode_action(c) -- Tagged union / optional body.
    local action = c:u(f.action, 1, "Action")
    if action == 0 then
        -- Clear carries no body in this invented protocol.
    elseif action == 1 then
        bd_addr(c)
    elseif action == 2 then
        c:u(f.connection_handle, 2, "Handle")
    else
        c:unknown("Unknown action; body layout is not known")
    end
end

local function decode_counted_bytes(c) -- CountFrom for bytes; a scalar follows the variable data.
    local n = c:u(f.length, 1, "Data Length")
    c:bytes(f.data, n, "Data")
    rssi(c)
end

local function decode_fixed_records(c) -- CountFrom + HciStruct, then a fixed-count scalar array.
    local n = c:u(f.count, 1, "Count")
    for i = 0, n - 1 do
        entry(c, i, "Record", function(e)
            e:u(f.connection_handle, 2, "Handle")
            rssi(e)
        end)
    end
    for _ = 1, 5 do c:u(f.value, 2, "Fixed Value") end -- Count = 5, ushort[5].
end

local function decode_cs_steps(c) -- Exact CsStepEntry field order; each record has its own length.
    local n = c:u(f.count, 1, "Num Steps Reported")
    for i = 0, n - 1 do
        entry(c, i, "Step", function(e)
            e:u(f.mode, 1, "Step Mode")
            e:u(f.channel, 1, "Step Channel")
            local length = e:u(f.step_length, 1, "Step Data Length")
            e:bytes(f.step_data, length, "Step Data")
        end)
    end
end

local function decode_tlvs(c) -- TLVs extend to the end of this message.
    local i = 0
    while c.off < c.limit do
        entry(c, i, "TLV", function(e)
            local kind = e:u(f.tlv_type, 1, "TLV Type")
            local n = e:u(f.length, 1, "TLV Length") -- Value length, not header length.
            local r = e:take(n, "TLV Value")
            -- An explicit sub-buffer prevents a decoder reading the next TLV.
            local child = cursor(r:tvb(), e.tree, 0, n)
            if kind == 1 then
                child:u(f.value, 2, "Value")
            elseif kind == 2 then
                child.tree:add_packet_field(f.text, child:take(n, "Text"), ENC_UTF_8)
            elseif kind == 3 then
                bd_addr(child)
            else
                child:unknown("Unknown TLV; skipped using its length")
            end
            child:finish()
        end)
        i = i + 1 -- Even length=0 advances by the two-byte TLV header.
    end
end

local function scanning_phy_params(c, phys) -- StructArg becomes an ordinary parameter.
    if band(phys, 0xFA) ~= 0 then
        c:unknown("Unsupported Scanning PHY bits; cannot assume future record sizes")
        return
    end
    for _, b in ipairs({0, 2}) do
        if band(phys, 2 ^ b) ~= 0 then
            entry(c, b, "PHY", function(e)
                e.tree:add(f.phy, b):set_generated()
                e:u(f.scan_type, 1, "Scan Type")
                local interval = e:u(f.interval, 2, "Scan Interval")
                local window = e:u(f.window, 2, "Scan Window")
                if window > interval then e:fail("malformed", "Scan Window exceeds Scan Interval") end
            end)
        end
    end
end

local function decode_scanning_phys(c)
    local phys = c:u(f.phys, 1, "Scanning PHYs")
    scanning_phy_params(c, phys)
end

local function decode_packed_values(c) -- Bitfield group, optional field, count from high nibble.
    local r = c:take(1, "Flags")
    local flags = c.tree:add(f.flags, r)
    flags:add(f.enabled, r)
    flags:add(f.packed_count, r) -- Masked field: feed the original byte.
    local raw = r:uint()
    local n = rshift(band(raw, 0xF0), 4)
    if band(raw, 1) ~= 0 then c:u(f.connection_handle, 2, "Optional Handle") end
    for _ = 1, n do c:u(f.value, 2, "Value") end
end

-- Tutorial kind → body parser. Keep each wire ID beside its named parser.
local tutorial_decoders = {
    [1] = decode_display_types,
    [2] = decode_action,
    [3] = decode_counted_bytes,
    [4] = decode_fixed_records,
    [5] = decode_cs_steps,
    [6] = decode_tlvs,
    [7] = decode_scanning_phys,
    [8] = decode_packed_values,
}

local function decode_sample(c)
    c:u(f.sample, 1, "Sample Value")
end

local function decode_message(c)
    local id = c:u(f.message_id, 2, "Message ID")
    if id == 1 then decode_sample(c)
    else c:unknown("Unknown message ID") end
end

local function decode_tutorial(c)
    local kind = c:u(f.kind, 1, "Tutorial Kind")
    local decode = tutorial_decoders[kind]
    if decode then decode(c) else c:unknown("Unknown tutorial kind") end
end

-- Vendor subevent → body parser.
return {
    [0xB0] = decode_sample,
    [0xA0] = decode_message,
    [0xE0] = decode_tutorial
}
