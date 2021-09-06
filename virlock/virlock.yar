rule Virlock {
   strings:
      $op0 = { 6a 40 68 00 10 00 00 68 00 }
      $op1 = { e9 00 00 00 00 81 ec }
      $op2 = { 03 00 00 be }
      
      $s1 = "kernel32.dll" ascii
      $s2 = "user32.dll" ascii
      $s3 = "!This program cannot be run in DOS mode."
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and all of ($s*) and
      all of ($op*)
}