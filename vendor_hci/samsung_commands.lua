-- Vendor Command bodies, starting after the opcode and HCI parameter length.
local f = require("samsung_fields").fields

local function decode_sample(c)
    c:u(f.sample, 1, "Sample Value")
end

-- Opcode → body parser. The same f.sample is used by the sample Events.
return {
    [0xFC01] = decode_sample
}
