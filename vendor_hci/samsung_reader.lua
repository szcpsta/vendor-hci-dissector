-- Common byte reader and tree helpers; no message routing or Proto registration.
local definitions = require("samsung_fields")
local f, ex = definitions.fields, definitions.experts

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
    c.tree:add(f.bd_addr, r, Address.ether(table.concat(octets, ":")))
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

local function is_input_error(err)
    return type(err) == "table" and err.marker == input_error
end

return {
    new = cursor,
    bd_addr = bd_addr,
    rssi = rssi,
    entry = entry,
    is_input_error = is_input_error
}
