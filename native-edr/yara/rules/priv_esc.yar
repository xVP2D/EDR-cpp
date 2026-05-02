rule PrivEsc {
    strings:
        $suid   = "chmod +s"
        $shadow = "/etc/shadow"
        $sudoer = "/etc/sudoers"
    condition:
        any of them
}
