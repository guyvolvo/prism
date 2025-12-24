rule PoetRat_Python
{
    meta:
        Author = "Nishan Maharjan"
        Description = "A yara rule to catch PoetRat python scripts"
        Data = "6th May 2020"
    strings:
        $encrptionFunction = "Affine" ascii wide
        $commands = /version|ls|cd|sysinfo|download|upload|shot|cp|mv|link|register|hid|compress|jobs|exit|tasklist|taskkill/ ascii wide
        $domain = "dellgenius.hopto.org" ascii wide

        $grammer_massacre = /BADD|Bad Error Happened/ ascii wide

        $mayBePresent = /self\.DIE|THE_GUID_KEY/ ascii wide
        $pipe_out = "Abibliophobia23" ascii wide
        $shot = "shot_{0}_{1}.png" ascii wide
    condition:
        3 of them