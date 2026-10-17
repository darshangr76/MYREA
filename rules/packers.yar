rule UPX_Signature {
    meta:
        description = "UPX packer signature"
        author = "MyREA"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx_magic = { 55 50 58 21 }    // "UPX!" stub
    condition:
        $upx_magic or (2 of ($upx*))
}

rule MPRESS_Signature {
    meta:
        description = "MPRESS packer signature"
    strings:
        $mpress = ".MPRESS1" ascii
        $mpress2 = ".MPRESS2" ascii
    condition:
        any of them
}

rule ASPack_Signature {
    meta:
        description = "ASPack packer signature"
    strings:
        $aspack = ".aspack" ascii
        $adata = ".adata" ascii
    condition:
        any of them
}

rule Themida_Signature {
    meta:
        description = "Themida / WinLicense packer sections"
    strings:
        $t1 = ".themida" ascii nocase
        $t2 = ".winlice" ascii nocase
    condition:
        any of them
}

rule VMProtect_Signature {
    meta:
        description = "VMProtect packer sections"
    strings:
        $v1 = ".vmp0" ascii
        $v2 = ".vmp1" ascii
        $v3 = ".vmp2" ascii
    condition:
        any of them
}
