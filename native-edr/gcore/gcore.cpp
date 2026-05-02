#include "gcore.hpp"
#include "logging.hpp"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <string>

void dump_process(int pid, const std::string &elf_path) {
    mkdir("/tmp/edr_dump", 0700);

    std::string basename = elf_path.substr(elf_path.rfind('/') + 1);
    std::string dump_path = "/tmp/edr_dump/" + std::to_string(pid) + "_" + basename;

    int src = open(elf_path.c_str(), O_RDONLY);
    if (src == -1) {
        edr::log::error("dump: impossible d'ouvrir " + elf_path);
        return;
    }

    int dst = open(dump_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (dst == -1) {
        edr::log::error("dump: impossible de créer " + dump_path);
        close(src);
        return;
    }

    struct stat st;
    fstat(src, &st);
    sendfile(dst, src, nullptr, st.st_size);

    close(src);
    close(dst);

    edr::log::info("dump pid=" + std::to_string(pid) + " " + std::to_string(st.st_size / 1024) + "KB " + dump_path);
}
