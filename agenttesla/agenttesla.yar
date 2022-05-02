rule win_agent_tesla_w0 {
    strings:
        $s0 = "SecretId1" ascii
        $s1 = "#GUID" ascii
        $s2 = "#Strings" ascii
        $s3 = "#Blob" ascii
        $s4 = "get_URL" ascii
        $s5 = "set_URL" ascii
        $s6 = "DecryptIePassword" ascii
        $s8 = "GetURLHashString" ascii
        $s9 = "DoesURLMatchWithHash" ascii

        $f0 = "GetSavedPasswords" ascii
        $f1 = "IESecretHeader" ascii
        $f2 = "RecoveredBrowserAccount" ascii
        $f4 = "PasswordDerivedBytes" ascii
        $f5 = "get_ASCII" ascii
        $f6 = "get_ComputerName" ascii
        $f7 = "get_WebServices" ascii
        $f8 = "get_UserName" ascii
        $f9 = "get_OSFullName" ascii
        $f10 = "ComputerInfo" ascii
        $f11 = "set_Sendwebcam" ascii
        $f12 = "get_Clipboard" ascii
        $f13 = "get_TotalFreeSpace" ascii
        $f14 = "get_IsAttached" ascii

        $x1 = "webpanel" ascii wide nocase
        $x2 = "smtp" ascii wide nocase

        $v5 = "vmware" ascii wide nocase
        $v6 = "VirtualBox" ascii wide nocase
        $v7 = "vbox" ascii wide nocase
        $v9 = "avghookx.dll" ascii wide nocase

    condition:
        (
            3 of ($s*) or
            7 of ($f*)
        ) and(
            all of ($x*) or
            3 of ($v*)
        )
}
