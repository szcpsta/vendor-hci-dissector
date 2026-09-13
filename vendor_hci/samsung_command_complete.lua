-- Completed opcode → return-parameter parser.
-- BluetoothKit 999c164 defines no known Samsung Command Complete return layout.
-- Keep this empty until a layout is known; the caller preserves raw bytes and
-- reports an unknown format. A handler starts immediately after the opcode.
return {}
