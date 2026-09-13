-- Teaching dissector, tested with Wireshark 4.4.8 / Lua 5.4.6.
-- FC01, B0 and A0:0001 mirror SampleVendorContract. E0 cases are invented.
-- Load explicitly; then select BT HCI Vendor -> BluetoothKit Vendor Tutorial.
local p = Proto("bkv", "BluetoothKit Vendor Tutorial")
local band, rshift = bit.band, bit.rshift
local event_code = Field.new("bthci_evt.code")
local command_opcode = Field.new("bthci_cmd.opcode")
local f = {
    route = ProtoField.uint8("bkv.route", "Vendor Subevent", base.HEX),
    message = ProtoField.uint16("bkv.message_id", "Message ID", base.HEX),
    sample = ProtoField.uint8("bkv.sample", "Sample Value", base.DEC),
    kind = ProtoField.uint8("bkv.kind", "Tutorial Kind", base.HEX, {
        [1] = "Display types", [2] = "Conditional body", [3] = "Counted bytes",
        [4] = "Fixed records", [5] = "Variable records", [6] = "TLV",
        [7] = "Context-dependent PHY records", [8] = "Bitfield count"
    }),
    status = ProtoField.uint8("bkv.status", "Status", base.HEX,
        {[0] = "Success", [1] = "Rejected", [2] = "Busy"}),
    handle = ProtoField.uint16("bkv.handle", "Connection Handle", base.HEX),
    lap = ProtoField.uint24("bkv.lap", "LAP", base.HEX),
    counter = ProtoField.uint64("bkv.counter", "Counter", base.DEC),
    address = ProtoField.ether("bkv.address", "BD_ADDR"),
    rssi = ProtoField.int8("bkv.rssi", "RSSI", base.DEC),
    slots = ProtoField.uint16("bkv.slots", "Interval (slots)", base.DEC),
    ms = ProtoField.double("bkv.interval_ms", "Interval (ms)"),
    ip = ProtoField.ipv4("bkv.ip", "IPv4"),
    length = ProtoField.uint8("bkv.length", "Data Length", base.DEC),
    text = ProtoField.string("bkv.text", "Text"),
    data = ProtoField.bytes("bkv.data", "Data"),
    raw = ProtoField.bytes("bkv.raw", "Undecoded Bytes"),
    action = ProtoField.uint8("bkv.action", "Action", base.DEC,
        {[0] = "Clear", [1] = "By address", [2] = "By handle"}),
    count = ProtoField.uint8("bkv.count", "Count", base.DEC),
    index = ProtoField.uint16("bkv.index", "Entry Index", base.DEC),
    mode = ProtoField.uint8("bkv.step.mode", "Step Mode", base.DEC),
    channel = ProtoField.uint8("bkv.step.channel", "Step Channel", base.DEC),
    step_length = ProtoField.uint8("bkv.step.length", "Step Data Length", base.DEC),
    step_data = ProtoField.bytes("bkv.step.data", "Step Data"),
    tlv_type = ProtoField.uint8("bkv.tlv.type", "TLV Type", base.HEX),
    value = ProtoField.uint16("bkv.value", "Value", base.DEC),
    phys = ProtoField.uint8("bkv.phys", "Scanning PHYs", base.HEX),
    phy = ProtoField.uint8("bkv.phy", "PHY Bit", base.DEC,
        {[0] = "LE 1M", [2] = "LE Coded"}),
    scan_type = ProtoField.uint8("bkv.scan_type", "Scan Type", base.DEC,
        {[0] = "Passive", [1] = "Active"}),
    interval = ProtoField.uint16("bkv.scan_interval", "Scan Interval", base.DEC),
    window = ProtoField.uint16("bkv.scan_window", "Scan Window", base.DEC),
    flags = ProtoField.uint8("bkv.flags", "Flags", base.HEX),
    enabled = ProtoField.bool("bkv.enabled", "Enabled", 8, {"Enabled", "Disabled"}, 0x01),
    packed_count = ProtoField.uint8("bkv.packed_count", "Packed Count", base.DEC, nil, 0xF0)
}
p.fields = f -- Register once, outside the per-packet callback.
local ex = {
    malformed = ProtoExpert.new("bkv.malformed", "Invalid vendor payload",
        expert.group.MALFORMED, expert.severity.ERROR),
    truncated = ProtoExpert.new("bkv.truncated", "Capture does not contain required bytes",
        expert.group.UNDECODED, expert.severity.WARN),
    unknown = ProtoExpert.new("bkv.unknown", "Unknown vendor layout",
        expert.group.UNDECODED, expert.severity.NOTE)
}
p.experts = ex

-- A small sequential reader. Expected input errors have a private marker;
-- programming errors are rethrown so Wireshark can report a Lua Error.
local input_error = {}
local C = {}
C.__index = C
local function cursor(tvb, tree, first, limit)
    return setmetatable({tvb = tvb, tree = tree, off = first, limit = limit}, C)
end
function C:fail(kind, text)
    error({marker = input_error, expert = ex[kind], tree = self.tree, text = text}, 0)
end
function C:take(n, label)
    if n < 0 or n % 1 ~= 0 then error("Invalid reader length") end
    if n > self.limit - self.off then
        self:fail("malformed", label .. ": exceeds declared message/block length")
    end
    if n > self.tvb:captured_len() - self.off then
        local kind = self.off + n <= self.tvb:reported_len() and "truncated" or "malformed"
        self:fail(kind, string.format("%s: need %d bytes at offset %d, captured %d",
            label, n, self.off, math.max(0, self.tvb:captured_len() - self.off)))
    end
    local r = self.tvb(self.off, n)
    self.off = self.off + n
    return r
end
function C:u(field, n, label)
    local r = self:take(n, label)
    self.tree:add_le(field, r)
    return r:le_uint()
end
function C:bytes(field, n, label)
    local r = self:take(n, label)
    self.tree:add(field, r)
    return r
end
function C:finish()
    if self.off ~= self.limit then
        self:fail("malformed", string.format("Unexpected trailing bytes: %d", self.limit - self.off))
    end
end
function C:unknown(label)
    self.tree:add_proto_expert_info(ex.unknown, label)
    self:bytes(f.raw, self.limit - self.off, "Unknown payload")
end
local function bd_addr(c)
    local r = c:take(6, "BD_ADDR")
    local octets = {}
    for i = 5, 0, -1 do octets[#octets + 1] = string.format("%02x", r(i, 1):uint()) end
    c.tree:add(f.address, r, Address.ether(table.concat(octets, ":")))
end
local function rssi(c)
    c.tree:add(f.rssi, c:take(1, "RSSI")):append_text(" dBm")
end
local function entry(c, i, name, decode)
    local first, parent = c.off, c.tree
    local node = parent:add(c.tvb(first, 0), string.format("%s[%d]", name, i))
    node:add(f.index, i):set_generated()
    c.tree = node
    decode(c)
    node:set_len(c.off - first)
    c.tree = parent
end

local cases = {}
cases[1] = function(c) -- Fixed widths, enum, signed value, address, text, computed field.
    c:u(f.status, 1, "Status")
    c:u(f.handle, 2, "Handle")
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
cases[2] = function(c) -- Tagged union / optional body.
    local action = c:u(f.action, 1, "Action")
    if action == 0 then
        -- Clear carries no body in this invented protocol.
    elseif action == 1 then
        bd_addr(c)
    elseif action == 2 then
        c:u(f.handle, 2, "Handle")
    else
        c:unknown("Unknown action; body layout is not known")
    end
end
cases[3] = function(c) -- CountFrom for bytes; a scalar follows the variable data.
    local n = c:u(f.length, 1, "Data Length")
    c:bytes(f.data, n, "Data")
    rssi(c)
end
cases[4] = function(c) -- CountFrom + HciStruct, then a fixed-count scalar array.
    local n = c:u(f.count, 1, "Count")
    for i = 0, n - 1 do
        entry(c, i, "Record", function(e)
            e:u(f.handle, 2, "Handle")
            rssi(e)
        end)
    end
    for _ = 1, 5 do c:u(f.value, 2, "Fixed Value") end -- Count = 5, ushort[5].
end
cases[5] = function(c) -- Exact CsStepEntry field order; each record has its own length.
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
cases[6] = function(c) -- TLVs extend to the end of this message.
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
cases[7] = function(c)
    local phys = c:u(f.phys, 1, "Scanning PHYs")
    scanning_phy_params(c, phys)
end
cases[8] = function(c) -- Bitfield group, optional field, count from high nibble.
    local r = c:take(1, "Flags")
    local flags = c.tree:add(f.flags, r)
    flags:add(f.enabled, r)
    flags:add(f.packed_count, r) -- Masked field: feed the original byte.
    local raw = r:uint()
    local n = rshift(band(raw, 0xF0), 4)
    if band(raw, 1) ~= 0 then c:u(f.handle, 2, "Optional Handle") end
    for _ = 1, n do c:u(f.value, 2, "Value") end
end

local function vendor_event(c)
    local route = c:u(f.route, 1, "Vendor Subevent")
    if route == 0xB0 then
        c:u(f.sample, 1, "Sample Value")
    elseif route == 0xA0 then
        local id = c:u(f.message, 2, "Message ID")
        if id == 1 then c:u(f.sample, 1, "Sample Value")
        else c:unknown("Unknown message ID") end
    elseif route == 0xE0 then -- Invented tutorial envelope, not a vendor specification.
        local kind = c:u(f.kind, 1, "Tutorial Kind")
        local decode = cases[kind]
        if decode then decode(c) else c:unknown("Unknown tutorial kind") end
    else
        c:unknown("Unknown vendor subevent")
    end
end

function p.dissector(tvb, pinfo, tree)
    -- This table receives HCI headers, with H4's packet-type byte already removed.
    -- Use fields already supplied by the native parent to distinguish Cmd from Evt.
    local ev, op = event_code(), command_opcode()
    if not ev and not op then return 0 end
    local root = tree:add(p, tvb())
    local c = cursor(tvb, root, 0, tvb:reported_len())
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
            vendor_event(c)
        elseif not ev then
            if opcode == 0xFC01 then c:u(f.sample, 1, "Sample Value")
            else c:unknown("Unknown vendor command") end
        elseif code == 0x0E then
            c:take(1, "Num HCI Command Packets")
            opcode = c:take(2, "Completed Opcode"):le_uint()
            -- The repository's sample leaves all vendor CC return parameters raw.
            c:unknown(string.format("Command Complete 0x%04X: return layout not defined", opcode))
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
        if type(err) == "table" and err.marker == input_error then
            err.tree:add_proto_expert_info(err.expert, err.text)
        else
            error(err, 0)
        end
    end
    pinfo.cols.info:append(" [BKV]")
    return tvb:captured_len() -- Return bytes handled, not a decoded model.
end

-- FT_NONE: select the vendor dissector through Decode As, not add(0xFC01, p).
DissectorTable.get("bthci_cmd.vendor"):add_for_decode_as(p)

-- Module result for the package entry point.
return p
