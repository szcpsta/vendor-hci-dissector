#!/usr/bin/env python3
"""Generate and check Samsung packets from BluetoothKit 999c164 with real TShark.

python3 tests/check_samsung.py /tmp/samsung-bt-status.btsnoop --check /path/to/tshark
The source commit supplies the layout and four original test packets; other
fixtures are synthetic, including FW Build ID values (not device captures).
"""
import argparse
import csv
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET

from make_examples import event, snoop


def fw_build_id(value):
    return event((b"\x63\x00\x00" + bytes((len(value),)) + value).hex())


def known(value):
    return {"subevent_code": "0x63", "bt_status.tag": "0x0000",
            "bt_status.fw_build_id_length": str(len(value.encode("utf-8"))),
            "bt_status.fw_build_id": value,
            "bt_status.fw_build_id_bytes": value.encode("utf-8").hex()}


CASES = [
    ("FW Build ID", fw_build_id(b"FW-2026.06.11"), known("FW-2026.06.11")),
    ("UTF-8 byte count", fw_build_id("삼성-FW".encode("utf-8")), known("삼성-FW")),
    ("Empty FW Build ID", fw_build_id(b""), known("")),
    ("Maximum HCI parameter length", fw_build_id(b"A" * 251), known("A" * 251)),
    # These four packets are copied verbatim from SamsungVendorDecoderTests.cs.
    ("Original unknown BT Status tag", bytes.fromhex("04 ff 05 63 34 12 aa bb"),
     {"subevent_code": "0x63", "bt_status.tag": "0x1234", "raw": "aabb", "unknown": True}),
    ("Original unknown event", bytes.fromhex("04 ff 03 10 aa bb"),
     {"subevent_code": "0x10", "raw": "aabb", "unknown": True}),
    ("Original unknown command", bytes.fromhex("01 01 fc 02 aa bb"),
     {"raw": "aabb", "unknown": True}),
    ("Original unknown Command Complete", bytes.fromhex("04 0e 05 01 01 fc 00 aa"),
     {"raw": "00aa", "unknown": True}),
    ("Unknown tag with no body", event("63 01 00"),
     {"bt_status.tag": "0x0001", "unknown": True}),
    ("Tutorial command disabled", bytes.fromhex("01 01 fc 01 42"), {"raw": "42", "unknown": True}),
    ("Tutorial B0 disabled", event("b0 43"), {"raw": "43", "unknown": True}),
    ("Tutorial A0 disabled", event("a0 01 00 44"), {"raw": "010044", "unknown": True}),
    ("Tutorial E0 disabled", event("e0 03 03 aa bb cc d6"), {"raw": "0303aabbccd6", "unknown": True}),
    ("Missing tag", event("63"), {"subevent_code": "0x63", "malformed": True}),
    ("Incomplete tag", event("63 00"), {"subevent_code": "0x63", "malformed": True}),
    ("Missing length", event("63 00 00"), {"bt_status.tag": "0x0000", "malformed": True}),
    ("Length exceeds body", event("63 00 00 03 41 42"),
     {"bt_status.fw_build_id_length": "3", "malformed": True}),
    ("Trailing byte", event("63 00 00 01 41 42"), {**known("A"), "malformed": True}),
    ("Trailing byte after empty string", event("63 00 00 00 41"), {**known(""), "malformed": True}),
    ("Length 252 cannot fit HCI parameters", event("63 00 00 fc" + " 41" * 251),
     {"bt_status.fw_build_id_length": "252", "malformed": True}),
    ("Invalid UTF-8 uses replacement", fw_build_id(b"A\xffB"),
     {"bt_status.fw_build_id": "A\ufffdB", "bt_status.fw_build_id_length": "3", "bt_status.fw_build_id_bytes": "41ff42"}),
    ("Embedded NUL preserves wire bytes", fw_build_id(b"A\x00B"),
     {"bt_status.fw_build_id": "A", "bt_status.fw_build_id_length": "3", "bt_status.fw_build_id_bytes": "410042"}),
]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("output", type=Path)
    ap.add_argument("--check", metavar="TSHARK")
    args = ap.parse_args()
    rows = [(packet, len(packet)) for _, packet, _ in CASES]
    # Distinguish a short capture from a complete packet with an invalid Length.
    full = fw_build_id(b"ABC")
    rows.append((full[:-1], len(full)))
    expectations = [expected for _, _, expected in CASES] + [
        {"bt_status.tag": "0x0000", "bt_status.fw_build_id_length": "3", "truncated": True}]
    args.output.write_bytes(snoop(rows))
    print(f"Wrote {len(rows)} Samsung frames to {args.output}")
    if not args.check:
        return
    script = Path(__file__).resolve().parents[1] / "vendor_hci" / "init.lua"
    executable = str(Path(args.check).resolve()) if Path(args.check).is_file() else args.check
    fields = sorted({key for e in expectations for key in e} | {"malformed", "truncated", "unknown", "sample", "kind"})
    prefix = "bthci_vendor.samsung."

    with tempfile.TemporaryDirectory(prefix="samsung verification ") as directory:
        env = os.environ.copy()
        env["WIRESHARK_CONFIG_DIR"] = str(Path(directory) / "config")
        env["WIRESHARK_PLUGIN_DIR"] = str(Path(directory) / "plugins")
        Path(env["WIRESHARK_CONFIG_DIR"]).mkdir()
        Path(env["WIRESHARK_PLUGIN_DIR"]).mkdir()

        def run(path, extra=(), installed=False):
            cmd = [executable, "-n", "-d", "bthci_cmd.vendor=bthci_vendor.samsung"]
            if not installed:
                cmd += ["-X", f"lua_script:{script}"]
            cmd += ["-r", str(path.resolve()), *extra]
            result = subprocess.run(cmd, text=True, encoding="utf-8", capture_output=True, check=True, env=env, cwd=directory)
            assert "Lua" not in result.stderr, result.stderr
            return result.stdout

        def read(path, extra=(), installed=False):
            options = [*extra, "-T", "fields", "-E", "occurrence=a"]
            for name in ["frame.number", *[prefix + f for f in fields], "_ws.lua.error"]:
                options += ["-e", name]
            return list(csv.reader(io.StringIO(run(path, options, installed)), delimiter="\t"))

        normal = read(args.output)
        assert len(normal) == len(rows)
        assert read(args.output, ["-2"]) == normal, "Redissection changed fields"
        for values, expected in zip(normal, expectations):
            assert values[-1] == "", (values[0], "Lua Error", values)
            actual = dict(zip(fields, values[1:-1]))
            for key, value in expected.items():
                assert (bool(actual[key]) if isinstance(value, bool) else actual[key]) == value, (values[0], key, actual[key], value)
            for key in ("malformed", "truncated", "unknown"):
                assert bool(actual[key]) == expected.get(key, False), (values[0], key, actual[key])
            assert not actual["sample"] and not actual["kind"], "Tutorial layout enabled by default"
            if "bt_status.fw_build_id" not in expected:
                assert not actual["bt_status.fw_build_id"], (values[0], "Unexpected FW Build ID")

        # Frozen output from the original C# decoder and SG, compiled at 999c164.
        # Match semantic values; native HCI owns standard header fields, and Lua
        # retains partial tree fields where C# instead returns HciInvalidDecoded.
        reference = json.loads((Path(__file__).parent / "fixtures" / "samsung_999c164.json").read_text(encoding="utf-8"))
        assert reference["source_commit"] == "999c164ab30f2f0fbb15cfe2f5f9a85e38b1bc81"
        by_packet = {packet.hex(): row for (_, packet, _), row in zip(CASES, normal)}
        mapping = {"Subevent Code": "subevent_code", "Tag": "bt_status.tag",
                   "Length": "bt_status.fw_build_id_length", "FW Build ID": "bt_status.fw_build_id", "Data": "raw"}
        for case in reference["cases"]:
            actual = dict(zip(fields, by_packet[case["packet"]][1:-1]))
            assert bool(actual["malformed"]) == (case["type"] == "HciInvalidDecoded"), case
            assert bool(actual["unknown"]) == case["type"].startswith("HciSamsungUnknown"), case
            if case["type"] == "HciInvalidDecoded":
                continue
            for name, expected in case["fields"].items():
                if name not in mapping:
                    continue
                if name == "FW Build ID":
                    expected = expected.split("\0", 1)[0]  # FT_STRING display limitation.
                    assert actual["bt_status.fw_build_id_bytes"] == case["packet"][14:], case
                elif name in ("Subevent Code", "Tag", "Data"):
                    expected = expected.lower()
                assert actual[mapping[name]] == expected, (case, name, actual[mapping[name]])

        # Check typed fields and exact source-byte highlighting, including length=0.
        packets = ET.fromstring(run(args.output, ["-T", "pdml"])).findall("packet")
        for i, length in enumerate((13, 9, 0, 251)):
            for suffix, pos, size in (("subevent_code", 3, 1), ("bt_status.tag", 4, 2),
                                      ("bt_status.fw_build_id_length", 6, 1), ("bt_status.fw_build_id", 7, length),
                                      ("bt_status.fw_build_id_bytes", 7, length)):
                node = packets[i].find(f".//field[@name='{prefix + suffix}']")
                if suffix == "bt_status.fw_build_id_bytes" and length == 0:
                    assert node is None  # Avoid Wireshark's <MISSING> label for zero-length bytes.
                    continue
                assert node is not None, (i + 1, suffix, "Missing field")
                assert (node.get("pos"), node.get("size")) == (str(pos), str(size)), (i + 1, suffix, node.attrib)
        for suffix, expression, expected_frames in (
            ("bt_status.tag", " == 0x1234", "5"),
            ("bt_status.fw_build_id", ' == "FW-2026.06.11"', "1"),
            ("bt_status.fw_build_id", ' == ""', "3\n19"),
            ("bt_status.fw_build_id_bytes", " == 41:00:42", "22"),
        ):
            output = run(args.output, ["-Y", prefix + suffix + expression, "-T", "fields", "-e", "frame.number"])
            assert output.strip() == expected_frames, (suffix, output)

        # Real routes still win with tutorials enabled.
        enabled = read(args.output, ["-o", prefix + "enable_tutorial:TRUE"])
        for i in (0, 1, 2, 3, 4, 8, *range(13, len(rows))):
            assert enabled[i] == normal[i], (i + 1, "Tutorial preference changed BT Status")

        cuts = [(packet[:n], len(packet)) for _, packet, expected in CASES
                if not expected.get("malformed") for n in range(1, len(packet))]
        cut_path = Path(directory) / "cuts.btsnoop"
        cut_path.write_bytes(snoop(cuts))
        output = read(cut_path)
        assert len(output) == len(cuts) and all(row[-1] == "" for row in output), "Lua Error in truncated input"
        shutil.copytree(script.parent, Path(env["WIRESHARK_PLUGIN_DIR"]) / "vendor_hci")
        assert read(args.output, installed=True) == normal, "Copied-plugin autoload changed fields"
    print(f"PASS: {len(rows)} Samsung cases, {len(reference['cases'])} C# reference comparisons, typed filters/byte ranges, two-pass, tutorial isolation, {len(cuts)} byte-boundary truncations, copied-plugin autoload")


if __name__ == "__main__":
    main()
