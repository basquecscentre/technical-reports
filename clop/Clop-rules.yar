rule win_clop_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.clop."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.clop"
        malpedia_rule_date = "20230124"
        malpedia_hash = "2ee0eebba83dce3d019a90519f2f972c0fcf9686"
        malpedia_version = "20230125"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { 56 53 8bf8 ff15???????? 8bf0 56 }
            // n = 6, score = 800
            //   56                   | push                esi
            //   53                   | push                ebx
            //   8bf8                 | mov                 edi, eax
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   56                   | push                esi

        $sequence_1 = { 8bf0 56 53 ff15???????? 50 ff15???????? 56 }
            // n = 7, score = 800
            //   8bf0                 | mov                 esi, eax
            //   56                   | push                esi
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   56                   | push                esi

        $sequence_2 = { 6a00 ff15???????? 68???????? 8bd8 }
            // n = 4, score = 800
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   68????????           |                     
            //   8bd8                 | mov                 ebx, eax

        $sequence_3 = { 6a04 6800300000 6887000000 6a00 }
            // n = 4, score = 800
            //   6a04                 | push                4
            //   6800300000           | push                0x3000
            //   6887000000           | push                0x87
            //   6a00                 | push                0

        $sequence_4 = { 83c40c 6860070000 6a40 ff15???????? }
            // n = 4, score = 800
            //   83c40c               | add                 esp, 0xc
            //   6860070000           | push                0x760
            //   6a40                 | push                0x40
            //   ff15????????         |                     

        $sequence_5 = { 50 ff15???????? 83c40c 6860070000 }
            // n = 4, score = 600
            //   50                   | push                eax
            //   ff15????????         |                     
            //   83c40c               | add                 esp, 0xc
            //   6860070000           | push                0x760

        $sequence_6 = { 6a00 8d45f8 50 57 53 56 ff15???????? }
            // n = 7, score = 600
            //   6a00                 | push                0
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   57                   | push                edi
            //   53                   | push                ebx
            //   56                   | push                esi
            //   ff15????????         |                     

        $sequence_7 = { 55 8bec 83ec1c 8d45ec }
            // n = 4, score = 500
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec1c               | sub                 esp, 0x1c
            //   8d45ec               | lea                 eax, [ebp - 0x14]

        $sequence_8 = { 6888130000 ffd7 6a00 6a00 }
            // n = 4, score = 500
            //   6888130000           | push                0x1388
            //   ffd7                 | call                edi
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_9 = { 0f85aa010000 68???????? 8d442450 50 }
            // n = 4, score = 500
            //   0f85aa010000         | jne                 0x1b0
            //   68????????           |                     
            //   8d442450             | lea                 eax, [esp + 0x50]
            //   50                   | push                eax

        $sequence_10 = { 50 ffd3 8d85d4f7ffff 50 }
            // n = 4, score = 500
            //   50                   | push                eax
            //   ffd3                 | call                ebx
            //   8d85d4f7ffff         | lea                 eax, [ebp - 0x82c]
            //   50                   | push                eax

        $sequence_11 = { 68???????? 68???????? e8???????? 83c424 6aff }
            // n = 5, score = 400
            //   68????????           |                     
            //   68????????           |                     
            //   e8????????           |                     
            //   83c424               | add                 esp, 0x24
            //   6aff                 | push                -1

        $sequence_12 = { ff15???????? 68???????? 8d85dcf7ffff 50 }
            // n = 4, score = 400
            //   ff15????????         |                     
            //   68????????           |                     
            //   8d85dcf7ffff         | lea                 eax, [ebp - 0x824]
            //   50                   | push                eax

        $sequence_13 = { 8d85bcefffff 50 ff15???????? 68???????? }
            // n = 4, score = 400
            //   8d85bcefffff         | lea                 eax, [ebp - 0x1044]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   68????????           |                     

        $sequence_14 = { 83c424 53 50 ffd6 }
            // n = 4, score = 300
            //   83c424               | add                 esp, 0x24
            //   53                   | push                ebx
            //   50                   | push                eax
            //   ffd6                 | call                esi

        $sequence_15 = { 6aff ffd7 8b4dfc 33c0 }
            // n = 4, score = 300
            //   6aff                 | push                -1
            //   ffd7                 | call                edi
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   33c0                 | xor                 eax, eax

        $sequence_16 = { 83c40c 33f6 85ff 7428 }
            // n = 4, score = 300
            //   83c40c               | add                 esp, 0xc
            //   33f6                 | xor                 esi, esi
            //   85ff                 | test                edi, edi
            //   7428                 | je                  0x2a

        $sequence_17 = { 8d85c8efffff 50 6a08 6a01 ff15???????? 85c0 }
            // n = 6, score = 300
            //   8d85c8efffff         | lea                 eax, [ebp - 0x1038]
            //   50                   | push                eax
            //   6a08                 | push                8
            //   6a01                 | push                1
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_18 = { 83c408 6aff ff15???????? 33c0 }
            // n = 4, score = 300
            //   83c408               | add                 esp, 8
            //   6aff                 | push                -1
            //   ff15????????         |                     
            //   33c0                 | xor                 eax, eax

        $sequence_19 = { 8b35???????? 8bf8 8b1d???????? 897c2418 83ffff }
            // n = 5, score = 200
            //   8b35????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   8b1d????????         |                     
            //   897c2418             | mov                 dword ptr [esp + 0x18], edi
            //   83ffff               | cmp                 edi, -1

    condition:
        7 of them and filesize < 796672
}
rule ClopELF
{
    meta:
        author = "@Tera0017/@SentinelLabs"
        description = "Temp Clop ELF variant yara rule based on $hash"
        reference = "https://s1.ai/Clop-ELF”
        hash = "09d6dab9b70a74f61c41eaa485b37de9a40c86b6d2eae7413db11b4e6a8256ef"
    strings:
        $code1 = {C7 45 ?? 00 E1 F5 05}
        $code2 = {81 7D ?? 00 E1 F5 05}
        $code3 = {C7 44 24 ?? 75 00 00 00}
        $code4 = {C7 44 24 ?? 80 01 00 00}
        $code5 = {C7 00 2E [3] C7 40 04}
        $code6 = {25 00 F0 00 00 3D 00 40 00 00}
        $code7 = {C7 44 24 04 [4] C7 04 24 [4] E8 [4] C7 04 24 FF FF FF FF E8 [4] C9 C3}
    condition:
        uint32(0) == 0x464c457f and all of them
}