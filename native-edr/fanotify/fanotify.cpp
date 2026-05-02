#include "logging.hpp"
#include "gcore.hpp"

#include <fcntl.h>
#include <sys/fanotify.h>
#include <unistd.h>
#include <climits>
#include <string>

static std::string get_path(int fd) {
    char buf[PATH_MAX];
    std::string proc = "/proc/self/fd/" + std::to_string(fd);
    ssize_t len = readlink(proc.c_str(), buf, sizeof(buf) - 1);
    if (len == -1)
        return "<inconnu>";
    buf[len] = '\0';
    return buf;
}

static bool is_elf(int fd) {
    unsigned char magic[4];
    ssize_t n = pread(fd, magic, sizeof(magic), 0);
    if (n < 4)
        return false;
    return magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F';
}

int run_fanotify() {
    edr::log::init("fanotify");

    int fan_fd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_NOTIF, O_RDONLY);
    if (fan_fd == -1) {
        edr::log::error("fanotify_init failed");
        return 1;
    }

    for (const char *path : { "/", "/tmp" }) {
        if (fanotify_mark(fan_fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                          FAN_CLOSE_WRITE, AT_FDCWD, path) == -1)
            edr::log::warn(std::string("fanotify_mark ignore: ") + path);
        else
            edr::log::info(std::string("surveillance filesystem: ") + path);
    }

    edr::log::info("En ecoute sur tous les filesystems");

    char buf[4096];
    while (true) {
        ssize_t len = read(fan_fd, buf, sizeof(buf));
        if (len == -1)
            break;

        auto *meta = reinterpret_cast<fanotify_event_metadata *>(buf);

        while (FAN_EVENT_OK(meta, len)) {
            std::string path = get_path(meta->fd);
            std::string pid  = std::to_string(meta->pid);

            if (is_elf(meta->fd) && path.rfind("/tmp/edr_dump/", 0) != 0) {
                edr::log::warn("ELF DETECTE pid=" + pid + " " + path);
                dump_process(meta->pid, path);
            }

            close(meta->fd);
            meta = FAN_EVENT_NEXT(meta, len);
        }
    }

    close(fan_fd);
    edr::log::shutdown();
    return 0;
}
