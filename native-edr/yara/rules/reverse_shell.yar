rule ReverseShell {
    strings:
        $nc   = "nc -e"
        $bash = "/bin/bash -i"
        $sh   = "/bin/sh -i"
    condition:
        any of them
}
