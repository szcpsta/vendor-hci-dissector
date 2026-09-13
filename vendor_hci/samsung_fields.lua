-- Shared filter definitions. Command/Event parsers reuse these same objects.
-- Keep bthci_vendor.samsung.* abbreviations stable: display filters and exports depend on them.
local f = {
    subevent_code = ProtoField.uint8("bthci_vendor.samsung.subevent_code", "Vendor Subevent", base.HEX,
        {[0x63] = "BT Status"}),
    bt_status_tag = ProtoField.uint16("bthci_vendor.samsung.bt_status.tag", "BT Status Tag", base.HEX,
        {[0x0000] = "FW Build ID"}),
    fw_build_id_length = ProtoField.uint8("bthci_vendor.samsung.bt_status.fw_build_id_length", "FW Build ID Length", base.DEC),
    fw_build_id = ProtoField.string("bthci_vendor.samsung.bt_status.fw_build_id", "FW Build ID"),
    fw_build_id_bytes = ProtoField.bytes("bthci_vendor.samsung.bt_status.fw_build_id_bytes", "FW Build ID Bytes"),
    -- The remaining layout-specific fields belong to the opt-in teaching examples.
    message_id = ProtoField.uint16("bthci_vendor.samsung.message_id", "Message ID", base.HEX),
    sample = ProtoField.uint8("bthci_vendor.samsung.sample", "Sample Value", base.DEC),
    kind = ProtoField.uint8("bthci_vendor.samsung.kind", "Tutorial Kind", base.HEX, {
        [1] = "Display types", [2] = "Conditional body", [3] = "Counted bytes",
        [4] = "Fixed records", [5] = "Variable records", [6] = "TLV",
        [7] = "Context-dependent PHY records", [8] = "Bitfield count"
    }),
    status = ProtoField.uint8("bthci_vendor.samsung.status", "Status", base.HEX,
        {[0] = "Success", [1] = "Rejected", [2] = "Busy"}),
    connection_handle = ProtoField.uint16("bthci_vendor.samsung.connection_handle", "Connection Handle", base.HEX),
    lap = ProtoField.uint24("bthci_vendor.samsung.lap", "LAP", base.HEX),
    counter = ProtoField.uint64("bthci_vendor.samsung.counter", "Counter", base.DEC),
    bd_addr = ProtoField.ether("bthci_vendor.samsung.bd_addr", "BD_ADDR"),
    rssi = ProtoField.int8("bthci_vendor.samsung.rssi", "RSSI", base.DEC),
    slots = ProtoField.uint16("bthci_vendor.samsung.slots", "Interval (slots)", base.DEC),
    ms = ProtoField.double("bthci_vendor.samsung.interval_ms", "Interval (ms)"),
    ip = ProtoField.ipv4("bthci_vendor.samsung.ip", "IPv4"),
    length = ProtoField.uint8("bthci_vendor.samsung.length", "Data Length", base.DEC),
    text = ProtoField.string("bthci_vendor.samsung.text", "Text"),
    data = ProtoField.bytes("bthci_vendor.samsung.data", "Data"),
    raw = ProtoField.bytes("bthci_vendor.samsung.raw", "Undecoded Bytes"),
    action = ProtoField.uint8("bthci_vendor.samsung.action", "Action", base.DEC,
        {[0] = "Clear", [1] = "By address", [2] = "By handle"}),
    count = ProtoField.uint8("bthci_vendor.samsung.count", "Count", base.DEC),
    index = ProtoField.uint16("bthci_vendor.samsung.index", "Entry Index", base.DEC),
    mode = ProtoField.uint8("bthci_vendor.samsung.step.mode", "Step Mode", base.DEC),
    channel = ProtoField.uint8("bthci_vendor.samsung.step.channel", "Step Channel", base.DEC),
    step_length = ProtoField.uint8("bthci_vendor.samsung.step.length", "Step Data Length", base.DEC),
    step_data = ProtoField.bytes("bthci_vendor.samsung.step.data", "Step Data"),
    tlv_type = ProtoField.uint8("bthci_vendor.samsung.tlv.type", "TLV Type", base.HEX),
    value = ProtoField.uint16("bthci_vendor.samsung.value", "Value", base.DEC),
    phys = ProtoField.uint8("bthci_vendor.samsung.phys", "Scanning PHYs", base.HEX),
    phy = ProtoField.uint8("bthci_vendor.samsung.phy", "PHY Bit", base.DEC,
        {[0] = "LE 1M", [2] = "LE Coded"}),
    scan_type = ProtoField.uint8("bthci_vendor.samsung.scan_type", "Scan Type", base.DEC,
        {[0] = "Passive", [1] = "Active"}),
    interval = ProtoField.uint16("bthci_vendor.samsung.scan_interval", "Scan Interval", base.DEC),
    window = ProtoField.uint16("bthci_vendor.samsung.scan_window", "Scan Window", base.DEC),
    flags = ProtoField.uint8("bthci_vendor.samsung.flags", "Flags", base.HEX),
    enabled = ProtoField.bool("bthci_vendor.samsung.enabled", "Enabled", 8, {"Enabled", "Disabled"}, 0x01),
    packed_count = ProtoField.uint8("bthci_vendor.samsung.packed_count", "Packed Count", base.DEC, nil, 0xF0)
}

local ex = {
    malformed = ProtoExpert.new("bthci_vendor.samsung.malformed", "Invalid vendor payload",
        expert.group.MALFORMED, expert.severity.ERROR),
    truncated = ProtoExpert.new("bthci_vendor.samsung.truncated", "Capture does not contain required bytes",
        expert.group.UNDECODED, expert.severity.WARN),
    unknown = ProtoExpert.new("bthci_vendor.samsung.unknown", "Unknown vendor layout",
        expert.group.UNDECODED, expert.severity.NOTE)
}

return {fields = f, experts = ex}
