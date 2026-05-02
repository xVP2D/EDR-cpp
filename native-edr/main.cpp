#include <sys/wait.h>
#include <unistd.h>
#include <cstdlib>

#include "fanotify/fanotify.hpp"
#include "dpi/dpi.hpp"
#include "kdetect/kdetect.hpp"
#include "yara/yara.hpp"

int main() {
    pid_t pid_fan = fork();
    if (pid_fan < 0) return EXIT_FAILURE;
    if (pid_fan == 0) return run_fanotify();

    pid_t pid_dpi = fork();
    if (pid_dpi < 0) {
        waitpid(pid_fan, nullptr, 0);
        return EXIT_FAILURE;
    }
    if (pid_dpi == 0) return run_dpi();

    pid_t pid_kdetect = fork();
    if (pid_kdetect < 0) {
        waitpid(pid_fan, nullptr, 0);
        waitpid(pid_dpi, nullptr, 0);
        return EXIT_FAILURE;
    }
    if (pid_kdetect == 0) return run_kdetect();

    pid_t pid_yara = fork();
    if (pid_yara < 0) {
        waitpid(pid_fan,     nullptr, 0);
        waitpid(pid_dpi,     nullptr, 0);
        waitpid(pid_kdetect, nullptr, 0);
        return EXIT_FAILURE;
    }
    if (pid_yara == 0) return run_yara();

    waitpid(pid_fan,     nullptr, 0);
    waitpid(pid_dpi,     nullptr, 0);
    waitpid(pid_kdetect, nullptr, 0);
    waitpid(pid_yara,    nullptr, 0);
    return EXIT_SUCCESS;
}
