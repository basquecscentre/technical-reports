rule Payload_Win_Strela{
    meta:
        author = "Innotec"
        description = "Detects Strela Stealer Payload Windows"
    strings:
        $ = "SOFTWARE\\Microsoft\\Office\\16.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676\\" ascii
        $ = "%s%s\\logins.json" ascii
        $ = "%s%s\\key4.db" ascii
        $ = "IMAP User" ascii
        $ = "/server.php" ascii
        $ = "POST" ascii
        $ = "IMAP Server" ascii
        $ = "IMAP Password" ascii
        $ = "Die Datei ist besch" ascii
        $ = "El archivo est" ascii
        $ = "danneggiato e non pu" ascii
        $ = "essere eseguito." ascii
        $ = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36" ascii
        $ = "ado y no se puede ejecutar." ascii
        $ = "\\Thunderbird\\Profiles\\" ascii
    condition:
        uint16(0) == 0x5a4d and (10 of them)
}
