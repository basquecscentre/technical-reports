rule MALWARE_Win_Mallox {
    meta:
        author = "voidm4p"
        description = "Detects Mallox Ransomware Windows"
    strings:
        $x1 = "Run TOR browser and open the site" ascii
        $x2 = "/C sc delete" ascii
        $x3 = "expand 32-byte k" ascii
        $x4= "Your files are encrypted and can not be used" ascii
        $x5 = "TargetID=" ascii
        
        $s1 = "vssadmin.exe" wide
        $s2 = "taskkill.exe" wide
        $s3 = "diskshadow.exe" wide
        $s4 = "delete shadows" wide
        $s5 = "-path" wide
        $s6 = ".deskthemepack" wide
        $s7 = "Download and install TOR" ascii
        $s8 = ".onion" ascii
        $s9 = "net.exe" wide
        $s10 = "bcdedit.exe" wide
        $s11 = "AdjustTokenPrivileges" ascii
    condition:
        uint16(0) == 0x5a4d and (3 of ($x*) or (1 of ($x*) and 4 of ($s*)) or 6 of ($s*))
}
