rule Nokoyawa: Nokoyawa
{
    strings:
        
        $s1 = "CIS lang detected! Stop working" ascii
        $s2 = "Successfully deleted shadow copies from" ascii
        $s3 = "Couldn't create ransom note" ascii
        $s4 = "Couldn't seek file:" ascii
        $s5 = "Couldn't read file:" ascii
        $s6 = "Couldn't write to file:" ascii
        $s6 = "Couldn't rename file" ascii
        
    condition:
        uint16(0) == 0x5A4D and all of ($s*)
}

rule Nokoyawa: Nevada
{
    strings:
        
        $s1 = "CIS. STOP!" ascii
        $s2 = "Shadow copies deleted from" ascii
        $s3 = "Failed to create ransom note" ascii
        $s4 = "Failed to seek file:" ascii
        $s5 = "Failed to read file:" ascii
        $s6 = "Failed to write file:" ascii
        $s6 = "Failed to rename file:" ascii
        
    condition:
        uint16(0) == 0x5A4D and all of ($s*)
}

