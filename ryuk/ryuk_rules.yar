private rule WindowsPE
{
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}

rule Ryuk_SequentialComparisons
{
meta:
author = "Malware Utkonos"
date = "2020-02-29"
description = "Sequential comparison of SID lookup result characters."
strings:
$op1 = { FF 15 [5-26] 83 ?? 4E 75 [2-26] 83 [1-2] 54 75 [2-26] 83 [1-2] 41 75 }
condition:
WindowsPE and all of them
}

rule Ryuk_SequentialComparisons_A
{
meta:
author = "Malware Utkonos"
date = "2020-01-29"
description = "Sequential comparison of SID lookup result characters, variant A."
strings:
$op1 = { FF 15 [4] 66 83 ?? 4E 75 ?? 66 83 ?? ?? 54 75 ?? 66 83 ?? ?? 41 75 }
condition:
WindowsPE and all of them
}

rule Ryuk_SequentialComparisons_B
{
meta:
author = "Malware Utkonos"
date = "2020-02-29"
description = "Sequential comparison of SID lookup result characters, variant B."
strings:
$op1 = { FF 15 [5-21] 0F B7 [2] 83 ?? 4E 75 [2-21] 0F B7 [2] 83 ?? 54 75 [2-21] 0F B7 [2] 83 ?? 41 75 }
condition:
WindowsPE and all of them
}

/*
   Yara Rule Set
   Author: Colin Cowie
   Date: 2018-10-19
   Reference: https://research.checkpoint.com/ryuk-ransomware-targeted-campaign-break/
*/

/* Rule Set ----------------------------------------------------------------- */

rule Ryuk_Dropper{
   meta:
      description = "Detects Ryuk dropper binary"
      author = "Colin Cowie"
   strings:
      $s1 = "\\users\\Public\\window.bat" ascii wide
      $s2 = "Main Invoked" ascii wide
      $s3 = "somedll.dll" ascii wide
      $s4 = "vssadmin resize shadowstorage" ascii wide
      $s5 = "InvokeMainViaCRT" ascii wide
   condition:
      3 of them
}

rule Ryuk_Payload{
   meta:
      description = "Detects Ryuk payload binary"
      author = "Colin Cowie"
   strings:
      $s1 = "UNIQUE_ID_DO_NOT_REMOVE" ascii wide
      $s2 = ".RYK" ascii wide
      $s3 = "RyukReadMe.txt" ascii wide
      $s4 = "fg4tgf4f3.dll" ascii wide
      $s5 = "2 files we unlock for free"
      $s6 = "Backups were either encrypted"
      $s7 = "HERMES"
      $s8 = "AhnLab"
   condition:
      4 of them
}

