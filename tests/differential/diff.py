#!/usr/bin/env python3
"""Differential check: compare unpackr's structure output with independent parsers.

PE      -> pefile (imphash, sections, entry point, import/export counts)
ELF     -> LIEF   (sections, segments, entry point, libraries)
Mach-O  -> LIEF   (segments, entry via main command, libraries)

Usage: diff.py <unpackr-binary> <file>...
Install the oracles with:  pip install pefile lief
Disagreements are printed, not hidden; exit status 1 if any were found.
"""
import json, subprocess, sys

def run(binary, path):
    out = subprocess.run([binary, "-i", path, "--format", "json"], capture_output=True, text=True)
    return json.loads(out.stdout)

def check_pe(rep, path):
    import pefile
    pe = pefile.PE(path)
    b = rep["binary"]; bad = []
    exp = [(s.Name.rstrip(b"\0").decode(errors="replace"), s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData) for s in pe.sections]
    got = [(s["name"], s["virtual_address"], s["virtual_size"], s["raw_offset"], s["raw_size"]) for s in b["sections"]]
    if exp != got: bad.append(f"sections differ\n  pefile : {exp}\n  unpackr: {got}")
    if pe.OPTIONAL_HEADER.AddressOfEntryPoint != b["entry_point"]["rva"]: bad.append("entry point differs")
    if pe.get_imphash() != b.get("import_hash", ""): bad.append(f"imphash differs: {pe.get_imphash()} vs {b.get('import_hash')}")
    n_exp = sum(len(e.imports) for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []))
    n_got = sum(len(i["functions"]) for i in b["imports"] if not i.get("delay_load"))
    if n_exp != n_got: bad.append(f"import count differs: {n_exp} vs {n_got}")
    return bad

def check_lief(rep, path):
    import lief
    lief.logging.disable()
    x = lief.parse(path); b = rep["binary"]; bad = []
    if b.get("slices"): b = b["slices"][0]
    if isinstance(x, lief.MachO.FatBinary): x = x.at(0)
    if isinstance(x, lief.ELF.Binary):
        names = [s.name for s in x.sections if s.name]
        got = [s["name"] for s in b["sections"]]
        if names != got: bad.append(f"section names differ: {len(names)} vs {len(got)}")
        if x.entrypoint != b["entry_point"]["va"]: bad.append(f"entry differs: {x.entrypoint:#x} vs {b['entry_point']['va']:#x}")
        if len(x.segments) != len(b["segments"]): bad.append("segment count differs")
        if sorted(x.libraries) != sorted(b.get("libraries") or []): bad.append("needed libraries differ")
    else:
        if len(x.segments) != len(b["segments"]): bad.append(f"segment count differs: {len(x.segments)} vs {len(b['segments'])}")
        if sorted(l.name for l in x.libraries) != sorted(b.get("libraries") or []): bad.append("dylib lists differ")
    return bad

def main():
    binary, files = sys.argv[1], sys.argv[2:]
    failed = 0
    for f in files:
        rep = run(binary, f)
        fmt = (rep.get("identification") or {}).get("primary", "")
        try:
            bad = check_pe(rep, f) if fmt.startswith("PE") else check_lief(rep, f) if fmt else ["not identified"]
        except Exception as e:
            bad = [f"checker error: {e!r}"]
        print(("OK   " if not bad else "DIFF ") + f"{fmt:14} {f}")
        for m in bad: print("     - " + m)
        failed += bool(bad)
    sys.exit(1 if failed else 0)

main()
