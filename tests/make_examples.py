#!/usr/bin/env python3
"""Generate synthetic H4 btsnoop examples; optionally check them with real TShark.

python3 make_examples.py /tmp/vendor-hci-examples.btsnoop --check /path/to/tshark
No vendor data or third-party Python packages are required.
"""
import argparse
import csv
import io
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile


def event(payload):
    body = bytes.fromhex(payload)
    return bytes((4, 0xFF, len(body))) + body


def snoop(rows):
    data = bytearray(b"btsnoop\0" + struct.pack(">II", 1, 1002))
    for i, (packet, reported) in enumerate(rows):
        flags = 2 if packet and packet[0] == 1 else 3
        data += struct.pack(">IIIIQ", reported, len(packet), flags, 0,
                            0x00DCDDB30F2F8000 + i * 1000)
        data += packet
    return data


# Expectations are stable filter values, not localized display labels.
CASES = [
    ("Sample Command", bytes.fromhex("01 01 fc 01 42"), {"sample": "66"}),
    ("Sample Subevent", event("b0 43"), {"sample": "67"}),
    ("Sample Message", event("a0 01 00 44"), {"sample": "68"}),
    ("Command Complete (unknown return format)", bytes.fromhex("04 0e 05 01 01 fc 00 44"), {"unknown": True}),
    ("Command Status", bytes.fromhex("04 0f 04 00 01 01 fc"), {}),
    ("Display types", event("e0 01 00 34 12 56 34 12 06 05 04 03 02 01 ff ee dd cc bb aa d6 10 00 c0 a8 01 02 03 42 54 21"),
     {"connection_handle": "0x1234", "status": "0x00", "bd_addr": "aa:bb:cc:dd:ee:ff", "rssi": "-42", "counter": "1108152157446", "interval_ms": "10", "text": "BT!"}),
    ("Action clear", event("e0 02 00"), {}),
    ("Action address", event("e0 02 01 ff ee dd cc bb aa"), {"bd_addr": "aa:bb:cc:dd:ee:ff"}),
    ("Action handle", event("e0 02 02 34 12"), {"connection_handle": "0x1234"}),
    ("Action unknown", event("e0 02 7f aa bb"), {"unknown": True}),
    ("Counted bytes followed by RSSI", event("e0 03 03 aa bb cc d6"), {"data": "aabbcc", "rssi": "-42"}),
    ("Zero length bytes followed by RSSI", event("e0 03 00 d6"), {"rssi": "-42"}),
    ("Two fixed records plus five ushorts", event("e0 04 02 34 12 d6 78 56 e2 01 00 02 00 03 00 04 00 05 00"),
     {"connection_handle": "0x1234,0x5678", "count": "2", "rssi": "-42,-30", "value": "1,2,3,4,5"}),
    ("Two variable CsStepEntry records", event("e0 05 02 01 25 02 aa bb 02 26 03 10 20 30"),
     {"count": "2", "step.mode": "1,2", "step.length": "2,3", "step.data": "aabb,102030"}),
    ("Zero records", event("e0 05 00"), {"count": "0"}),
    ("TLV known, unknown, empty, then known", event("e0 06 01 02 34 12 99 01 ff 99 00 02 03 42 54 21"),
     {"value": "4660", "text": "BT!", "unknown": True}),
    ("StructArg PHY bitmask", event("e0 07 05 01 10 00 08 00 00 20 00 10 00"),
     {"scan_interval": "16,32", "scan_window": "8,16"}),
    ("Count from bitfield plus optional handle", event("e0 08 21 34 12 01 00 02 00"),
     {"connection_handle": "0x1234", "packed_count": "2", "enabled": "True", "value": "1,2"}),
    ("No optional handle or values", event("e0 08 00"), {"packed_count": "0", "enabled": "False"}),
    ("Unknown message ID", event("a0 02 00 aa"), {"unknown": True}),
    ("Missing Sample Value", event("b0"), {"malformed": True}),
    ("Sample trailing bytes", event("b0 43 ff"), {"sample": "67", "malformed": True}),
    ("Inner length exceeds outer length", event("e0 03 04 aa bb d6"), {"malformed": True}),
    ("Short second step preserves first", event("e0 05 02 01 25 02 aa bb 02 26 03 10"),
     {"step.data": "aabb", "malformed": True}),
    ("TLV known type wrong size", event("e0 06 01 01 34"), {"malformed": True}),
    ("Window greater than interval", event("e0 07 01 01 08 00 10 00"), {"malformed": True}),
    ("Unknown PHY bit", event("e0 07 02 aa"), {"unknown": True}),
]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("output", type=Path)
    ap.add_argument("--check", metavar="TSHARK")
    args = ap.parse_args()
    rows = [(packet, len(packet)) for _, packet, _ in CASES]
    # Actual capture truncation: original length differs from included length.
    full = event("e0 03 03 aa bb cc d6")
    rows.append((full[:-2], len(full)))
    expectations = [expected for _, _, expected in CASES] + [{"truncated": True}]
    labels = [name for name, _, _ in CASES] + ["Capture truncated"]
    args.output.write_bytes(snoop(rows))
    print(f"Wrote {len(rows)} frames to {args.output}")
    for i, name in enumerate(labels, 1):
        print(f"{i:2}: {name}")
    if not args.check:
        return
    script = Path(__file__).resolve().parents[1] / "vendor_hci" / "init.lua"
    fields = sorted({key for e in expectations for key in e} | {"malformed", "truncated", "unknown"})
    command = [str(Path(args.check).resolve()) if Path(args.check).is_file() else args.check,
               "-n", "-d", "bthci_cmd.vendor=bthci_vendor.samsung"]
    script_args = ["-X", f"lua_script:{script}"]

    def read(path, two_pass=False, load_args=None, env=None, cwd=None):
        cmd = command + (script_args if load_args is None else load_args)
        cmd += (["-2"] if two_pass else []) + ["-r", str(path.resolve()), "-T", "fields", "-E", "occurrence=a"]
        for field in ["frame.number"] + ["bthci_vendor.samsung." + f for f in fields] + ["_ws.lua.error"]:
            cmd += ["-e", field]
        result = subprocess.run(cmd, text=True, capture_output=True, check=True, env=env, cwd=cwd)
        if "Lua" in result.stderr:
            raise AssertionError(result.stderr)
        return list(csv.reader(io.StringIO(result.stdout), delimiter="\t"))

    normal = read(args.output)
    assert len(normal) == len(rows)
    assert read(args.output, True) == normal, "Redissection changed field output"
    for values, expected in zip(normal, expectations):
        assert values[-1] == "", (values[0], "Unexpected Lua Error", values)
        actual = dict(zip(fields, values[1:-1]))
        for key, value in expected.items():
            assert (bool(actual[key]) if isinstance(value, bool) else actual[key]) == value, (values[0], key, actual[key], value)
        for key in ("malformed", "truncated", "unknown"):
            assert bool(actual[key]) == expected.get(key, False), (values[0], key, actual[key])
    # Every byte boundary of the valid fixtures, with reported length retained.
    cuts = [(packet[:n], len(packet)) for (_, packet, exp) in CASES
            if not exp.get("malformed") for n in range(1, len(packet))]
    with tempfile.TemporaryDirectory(prefix="samsung-cuts-") as directory:
        cut_path = Path(directory) / "cuts.btsnoop"
        cut_path.write_bytes(snoop(cuts))
        output = read(cut_path)
        assert len(output) == len(cuts)
        assert all(row[-1] == "" for row in output), "Lua Error in truncated input"
    # Exercise real folder installation too: 4.4 scans each Lua file separately.
    # Run outside the repository, with spaces in the path, and without -X.
    with tempfile.TemporaryDirectory(prefix="samsung plugin install ") as directory:
        plugins = Path(directory) / "plugins"
        shutil.copytree(script.parent, plugins / "vendor_hci")
        env = os.environ.copy()
        env["WIRESHARK_PLUGIN_DIR"] = str(plugins)
        assert read(args.output, load_args=[], env=env, cwd=directory) == normal, "Plugin installation changed field output"
    print(f"PASS: {len(rows)} field/diagnostic cases, one-pass vs two-pass, {len(cuts)} byte-boundary truncations, copied-plugin autoload")


if __name__ == "__main__":
    main()
