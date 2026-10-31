// UNPACKR built-in rules: languages, compilers and runtimes.
//
// Metadata contract (read by internal/yara):
//   name      display name; must equal the name the native detector uses
//   strength  strong | moderate | weak
//   status    tested        has positive and negative fixtures in this repository
//             experimental  written from format knowledge but not yet tested
//                           against real samples; reported, never counted as
//                           evidence
//   family    optional independence group; rules matching the same bytes as a
//             native detector reuse its family so agreement is not counted
//             as corroboration
//   description  one line shown to the analyst
//
// These rules are original to UNPACKR (Apache-2.0).

rule go_buildinfo : language {
    meta:
        name = "Go"
        strength = "strong"
        status = "tested"
        family = "go:buildinfo"
        description = "Go build information header"
    strings:
        $m = "\xff Go buildinf:"
    condition:
        $m
}

rule go_pclntab : language {
    meta:
        name = "Go"
        strength = "moderate"
        status = "tested"
        family = "go:pclntab"
        description = "Go runtime function table (pclntab) header"
    strings:
        $h = { (F0 | F1 | FA | FB) FF FF FF 00 00 (01 | 02 | 04) (04 | 08) }
    condition:
        $h
}

rule rust_std_path : language {
    meta:
        name = "Rust"
        strength = "strong"
        status = "tested"
        family = "rust:path"
        description = "rustc standard library source path in panic locations"
    strings:
        $p = /\/rustc\/[0-9a-f]{40}\//
    condition:
        $p
}

rule pyinstaller_archive : language {
    meta:
        name = "Python (bundled with PyInstaller)"
        strength = "strong"
        status = "tested"
        family = "pyi:cookie"
        description = "PyInstaller archive cookie"
    strings:
        $c = { 4D 45 49 0C 0B 0A 0B 0E }
    condition:
        $c
}

rule delphi_runtime : language {
    meta:
        name = "Delphi / Object Pascal"
        strength = "moderate"
        status = "experimental"
        description = "Delphi runtime strings"
    strings:
        $a = "Software\\Borland\\Delphi" ascii wide
        $b = "Embarcadero" ascii wide
    condition:
        any of them
}

rule autoit_script : language {
    meta:
        name = "AutoIt"
        strength = "moderate"
        status = "experimental"
        description = "AutoIt script interpreter marker"
    strings:
        $a = "AU3!EA06"
        $b = "This is a third-party compiled AutoIt script"
    condition:
        any of them
}
