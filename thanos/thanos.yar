rule Thanos {
   strings:
      $s1 = "SbieDll.dll" wide
      $s2 = "cmVzaXplIHNoYWRvd3N0b3JhZ2UgL2Zvcj1lOiAvb249ZTogL21heHNpemU9NDAxTUI=" wide
      $s3 = "!This program cannot be run in DOS mode."
      $s4 = "win32_processor" wide
      $s5 = "win32_logicaldisk.deviceid=" wide
      $s6 = "taskkill.exe" wide
      $s7 = "Select * from Win32_ComputerSystem" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and all of ($s*)
}