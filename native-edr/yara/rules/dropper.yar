rule Dropper {
    strings:
        $wget = "wget http"
        $curl = "curl http"
    condition:
        $wget or $curl
}
