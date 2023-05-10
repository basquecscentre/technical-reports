rule RoyalRansom
{
meta:
    author = "Max 'Libra' Kersten for Trellix' Advanced Research Center (ARC)"
    version = "1.0"
    description = "Detects the Windows and Linux versions of Royal Ransom"
    date = "20-03-2023"
    malware_type = "ransomware"

strings:
    $all_1 = "http://royal2xthig3ou5hd7zsliqagy6yygk2cdelaxtni2fyad6dpmpxedid.onion/%s"
    $all_2 = "In the meantime, let us explain this case.It may seem complicated, but it is not!"
    $all_3 = "Royal offers you a unique deal.For a modest royalty(got it; got it ? ) for our pentesting services we will not only provide you with an amazing risk mitigation service,"
    $all_4 = "Try Royal today and enter the new era of data security!"
    $all_5 = "We are looking to hearing from you soon!"

condition:
    all of ($all_*)
}
