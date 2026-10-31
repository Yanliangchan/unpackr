// UNPACKR built-in rules: packers, protectors and installers.
// See languages.yar for the metadata contract.

import "pe"

rule upx_magic : packer {
    meta:
        name = "UPX"
        strength = "strong"
        status = "tested"
        family = "sig:UPX"
        description = "UPX! header magic"
    strings:
        $m = "UPX!"
    condition:
        $m
}

rule upx_stub_banner : packer {
    meta:
        name = "UPX"
        strength = "strong"
        status = "tested"
        family = "sig:UPX"
        description = "UPX stub banner text"
    strings:
        $b = "This file is packed with the UPX executable packer"
    condition:
        $b
}

rule upx_pe_layout_without_magic : packer {
    meta:
        name = "UPX"
        strength = "moderate"
        status = "tested"
        family = "yara:upx-layout"
        description = "UPX section layout (UPX0/UPX1) with the UPX! magic removed, as done to defeat upx -d"
    strings:
        $m = "UPX!"
    condition:
        pe.is_pe and not $m and
        for any s in pe.sections : (s.name == "UPX0") and
        for any s in pe.sections : (s.name == "UPX1")
}

rule aspack : packer {
    meta:
        name = "ASPack"
        strength = "moderate"
        status = "experimental"
        description = "ASPack section names"
    condition:
        pe.is_pe and for any s in pe.sections : (s.name == ".aspack" or s.name == ".adata")
}

rule themida_winlicense : packer {
    meta:
        name = "Themida / WinLicense"
        strength = "moderate"
        status = "experimental"
        description = "Themida section name or marker string"
    strings:
        $s = "Themida" ascii wide
    condition:
        pe.is_pe and ($s or for any s in pe.sections : (s.name == ".themida" or s.name == ".winlice"))
}

rule vmprotect : packer {
    meta:
        name = "VMProtect"
        strength = "moderate"
        status = "experimental"
        description = "VMProtect section names"
    condition:
        pe.is_pe and for any s in pe.sections : (s.name == ".vmp0" or s.name == ".vmp1" or s.name == ".vmp2")
}

rule mpress : packer {
    meta:
        name = "MPRESS"
        strength = "moderate"
        status = "experimental"
        description = "MPRESS section names"
    condition:
        pe.is_pe and for any s in pe.sections : (s.name == ".MPRESS1" or s.name == ".MPRESS2")
}

rule pecompact : packer {
    meta:
        name = "PECompact"
        strength = "moderate"
        status = "experimental"
        description = "PECompact section names"
    condition:
        pe.is_pe and for any s in pe.sections : (s.name == "PEC2" or s.name == "PECompact2")
}

rule enigma_protector : packer {
    meta:
        name = "Enigma Protector"
        strength = "moderate"
        status = "experimental"
        description = "Enigma section names"
    condition:
        pe.is_pe and for any s in pe.sections : (s.name == ".enigma1" or s.name == ".enigma2")
}

rule nsis_installer : installer {
    meta:
        name = "NSIS installer"
        strength = "moderate"
        status = "experimental"
        description = "Nullsoft Scriptable Install System markers"
    strings:
        $a = "Nullsoft Install System"
        $b = "NullsoftInst"
    condition:
        any of them
}

rule inno_setup : installer {
    meta:
        name = "Inno Setup installer"
        strength = "moderate"
        status = "experimental"
        description = "Inno Setup markers"
    strings:
        $a = "Inno Setup Setup Data"
        $b = "JR.Inno.Setup"
    condition:
        any of them
}
