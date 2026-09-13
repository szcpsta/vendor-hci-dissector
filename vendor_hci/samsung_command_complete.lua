-- Completed opcode → return-parameter parser.
-- The sample contract does not define any vendor Command Complete return layout.
-- Keep this empty until a layout is known; the caller preserves raw bytes and
-- reports an unknown format. A handler starts immediately after the opcode.
return {}
