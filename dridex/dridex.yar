rule DridexV4
{
    meta:
        author = "kevoreilly"
        description = "Dridex v4 Payload"
        cape_type = "Dridex v4 Payload"
    strings:
        $decrypt32 = {6A 40 58 3B C8 0F 4D C1 39 46 04 7D 50 53 57 8B F8 81 E7 3F 00 00 80 79 05 4F 83 CF C0 47 F7 DF 99 1B FF 83 E2 3F 03 C2 F7 DF C1 F8 06 03 F8 C1 E7 06 57}
        $getproc32 = {81 FB ?? ?? ?? ?? 74 2D 8B CB E8 ?? ?? ?? ?? 85 C0 74 0C 8B C8 8B D7 E8 ?? ?? ?? ?? 5B 5F C3}
        $getproc64 = {81 FB ?? ?? ?? ?? 75 04 33 C0 EB 2D 8B CB E8 ?? ?? ?? ?? 48 85 C0 75 17 8B CB E8 ?? ?? ?? ?? 84 C0 74 E5 8B CB E8 ?? ?? ?? ?? 48 85 C0 74 D9 8B D7 48 8B C8 E8 ?? ?? ?? ?? 48 8B 5C 24 30 48 83 C4 20 5F C3}
        $bot_stub_32 = {8B 45 E? 8? [10-13] 8A 1C 0? [6-11] 05 FF 00 00 00 8B ?? F? 39 ?? 89 45 E? 72 D?}
        $bot_stub_64 = {8B 44 24 ?? 89 C1 89 CA 4C 8B 05 [4] 4C 8B 4C 24 ?? 45 8A 14 11 83 E0 1F 89 C0 41 89 C3 47 2A 14 18 44 88 54 14}
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule DridexLoader
{
    meta:
        author = "kevoreilly"
        description = "Dridex v4 dropper C2 parsing function"
        cape_type = "DridexLoader Payload"

    strings:
        $c2parse_1 = {57 0F 95 C0 89 35 [4] 88 46 04 33 FF 80 3D [4] 00 76 54 8B 04 FD [4] 8D 4D EC 83 65 F4 00 89 45 EC 66 8B 04 FD [4] 66 89 45 F0 8D 45 F8 50}
        $c2parse_2 = {89 45 00 0F B7 53 04 89 10 0F B6 4B 0C 83 F9 0A 7F 03 8A 53 0C 0F B6 53 0C 85 D2 7E B7 8D 74 24 0C C7 44 24 08 00 00 00 00 8D 04 7F 8D 8C 00}
        $c2parse_3 = {89 08 66 39 1D [4] A1 [4] 0F 95 C1 88 48 04 80 3D [4] 0A 77 05 A0 [4] 80 3D [4] 00 56 8B F3 76 4E 66 8B 04 F5}
        $c2parse_4 = {0F B7 C0 89 01 A0 [4] 3C 0A 77 ?? A0 [4] A0 [4] 57 33 FF 84 C0 74 ?? 56 BE}
        $c2parse_5 = {0F B7 05 [4] 89 02 89 15 [4] 0F B6 15 [4] 83 FA 0A 7F 07 0F B6 05 [4] 0F B6 05 [4] 85 C0}
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule DridexBotHook
{
	meta:
      description = "Detects latest Dridex bot hook "
      author = "@VK_Intel"
      reference = "internal"
      tlp = "white"
      date = "2020-03-24"

	strings:
		$code = { e8 ?? ?? ?? ?? 8b ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 44 2b f3 48 ?? ?? ?? 41 b8 04 00 00 00 41 83 ee 05 44 ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? ba cd 9c ff 56 b9 cb 69 e2 6a 8b f3 48 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 85 c0 74 ?? 48 ?? ?? ?? ?? 4c ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? 49 8b cd 41 b9 40 00 00 00 }
	condition:
		$code

}

rule DridexPayload
{
    meta:
        author = "kev"
        description = "Dridex encrypt/decrypt function"
        cape_type = "Dridex Payload"

    strings:
        $crypt_32_v1 = {57 53 55 81 EC 0C 02 00 00 8B BC 24 1C 02 00 00 85 FF 74 20 8B AC 24 20 02 00 00 85 ED 74 15 83 BC 24 24 02 00 00 00 74 0B 8B 9C 24 28 02 00 00 85 DB 75 ?? 81 C4 ?? 02 00 00 5D 5B 5F}
        $crypt_32_v2 = {56 57 53 55 81 EC 08 02 00 00 8B BC 24 1C 02 00 00 85 FF 74 20 8B AC 24 20 02 00 00 85 ED 74 15 83 BC 24 24 02 00 00 00 74 0B 8B 9C 24 28 02 00 00 85 DB 75 ?? 81 C4 ?? 02 00 00 5D 5B 5F}
        $crypt_32_v3 = {56 57 53 55 81 EC 08 02 00 00 8B E9 8B FA 85 ED 74 19 85 FF 74 15 83 BC 24 1C 02 00 00 00 74 0B 8B 9C 24 20 02 00 00 85 DB 75 0D}

        $crypt_64_v1 = {41 54 41 55 41 56 41 57 48 81 EC 48 02 00 00 49 89 CE 45 89 CC 4D 89 C5 41 89 D7 4D 85 F6 0F 84 41 02 00 00 45 85 FF 0F 84 38 02 00 00 4D 85 ED 0F 84 2F 02 00 00 45 85 E4 0F 84 26 02 00}
    
    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D 

        and 

        ($crypt_32_v1 or $crypt_32_v2 or $crypt_32_v3 or $crypt_64_v1)
}