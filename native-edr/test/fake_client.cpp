#include <iostream>
#include <unistd.h>
#include <sys/wait.h>
#include <csignal>
#include <cstdlib>

static void section(const char* msg) {
    std::cout << "\n\033[1;34m=== " << msg << " ===\033[0m\n";
}

static void ok(const char* msg) {
    std::cout << "\033[1;32m[+]\033[0m " << msg << "\n";
}

static int run(const char* const argv[]) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        execvp(argv[0], const_cast<char* const*>(argv));
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

int main() {
    std::cout << "\033[1mEDR Test Suite\033[0m — les alertes apparaissent dans /var/log/naive-edr/\n";
    section("Nettoyage");
    const char* remove[] = {"dnf", "remove", "-y", "tree", nullptr};
    run(remove);

    section("Test 1 : installation de tree  ->  fanotify + YARA rule=Test_Tree");
    ok("dnf install -y tree");
    const char* install[] = {"dnf", "install", "-y", "tree", nullptr};
    int ret = run(install);
    if (ret == 0)
        ok("tree installe — attendre le YARA MATCH dans yara.log");
    else
        std::cout << "  [!] dnf a retourne " << ret << " (tree peut-etre deja installe)\n";

    section("Test 2 : execution depuis /tmp  ->  kdetect T1059_exec_from_tmp");
    const char* cp[] = {"cp", "/bin/bash", "/tmp/edr_test_shell", nullptr};
    run(cp);
    ok("/tmp/edr_test_shell lance");
    const char* exec_tmp[] = {"/tmp/edr_test_shell", "-c", "echo 'kdetect test ok'", nullptr};
    run(exec_tmp);

    section("Test 3 : python3 depuis /tmp  ->  kdetect T1059_script_in_tmp");
    chdir("/tmp");
    ok("python3 avec cwd=/tmp (sleep 4s pour que kdetect scanne)");
    const char* py[] = {"python3", "-c", "import time; time.sleep(4)", nullptr};
    run(py);

    section("Test 4 : netcat  ->  kdetect T1059_netcat_detected");
    ok("nc -l 19999 (4s)");
    pid_t nc_pid = fork();
    if (nc_pid == 0) {
        const char* nc[] = {"nc", "-l", "19999", nullptr};
        execvp("nc", const_cast<char* const*>(nc));
        _exit(127);
    }
    if (nc_pid > 0) {
        sleep(4);
        kill(nc_pid, SIGTERM);
        waitpid(nc_pid, nullptr, 0);
    }


    std::cout << "\n\033[1mFin des tests.\033[0m\n"
              << "Logs a verifier :\n"
              << "  /var/log/naive-edr/fanotify.log\n"
              << "  /var/log/naive-edr/yara.log\n"
              << "  /var/log/naive-edr/kdetect.log\n";
    return 0;
}
