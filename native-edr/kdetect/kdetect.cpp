#include <fstream>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <filesystem>
#include <thread>
#include <chrono>
#include <unistd.h>
#include <algorithm>

#include "logging.hpp"

namespace fs = std::filesystem;

struct ProcessInfo {
    int         pid;
    int         ppid;
    std::string name;
    std::string exe;
    std::string cwd;
    std::string cmdline;
};

static void sendAlert(const std::string& rule, const ProcessInfo& p) {
    edr::log::warn("ALERT rule=" + rule +
                   " pid="  + std::to_string(p.pid) +
                   " ppid=" + std::to_string(p.ppid) +
                   " name=" + p.name +
                   " exe="  + p.exe +
                   " cwd="  + p.cwd);
}

static ProcessInfo readProcess(int pid) {
    ProcessInfo p;
    p.pid = pid;

    std::ifstream status("/proc/" + std::to_string(pid) + "/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.rfind("Name:", 0) == 0) p.name = line.substr(6);
        if (line.rfind("PPid:", 0) == 0) p.ppid = std::stoi(line.substr(6));
    }

    try {
        p.exe = fs::read_symlink("/proc/" + std::to_string(pid) + "/exe").string();
    } catch (...) { p.exe = ""; }

    try {
        p.cwd = fs::read_symlink("/proc/" + std::to_string(pid) + "/cwd").string();
    } catch (...) { p.cwd = ""; }

    std::ifstream cmdfile("/proc/" + std::to_string(pid) + "/cmdline");
    std::getline(cmdfile, p.cmdline);

    return p;
}

static std::vector<int> listPids() {
    std::vector<int> pids;
    for (const auto& entry : fs::directory_iterator("/proc")) {
        std::string name = entry.path().filename().string();
        bool is_number = !name.empty() &&
                         std::all_of(name.begin(), name.end(), ::isdigit);
        if (is_number) pids.push_back(std::stoi(name));
    }
    return pids;
}

static int countConnections(int pid) {
    int count = 0;
    std::ifstream tcp("/proc/" + std::to_string(pid) + "/net/tcp");
    std::string line;
    std::getline(tcp, line);
    while (std::getline(tcp, line)) count++;
    return count;
}

static void checkRules(const ProcessInfo& p, std::map<int, std::set<std::string>>& alerted) {
    auto& already = alerted[p.pid];

    if ((p.name == "bash" || p.name == "sh" || p.name == "zsh") &&
        (p.cwd.rfind("/tmp",     0) == 0 ||
         p.cwd.rfind("/dev/shm", 0) == 0 ||
         p.cwd.rfind("/var/www", 0) == 0)) {
        if (!already.count("shell_in_tmp")) {
            sendAlert("T1059_shell_in_tmp", p);
            already.insert("shell_in_tmp");
        }
    }

    if (p.exe.rfind("/tmp",     0) == 0 ||
        p.exe.rfind("/dev/shm", 0) == 0) {
        if (!already.count("exec_from_tmp")) {
            sendAlert("T1059_exec_from_tmp", p);
            already.insert("exec_from_tmp");
        }
    }

    if (p.name == "nc" || p.name == "ncat" || p.name == "netcat") {
        if (!already.count("netcat")) {
            sendAlert("T1059_netcat_detected", p);
            already.insert("netcat");
        }
    }

    if (p.exe.find("(deleted)") != std::string::npos) {
        if (!already.count("deleted_exe")) {
            sendAlert("T1036_deleted_binary", p);
            already.insert("deleted_exe");
        }
    }

    if (countConnections(p.pid) > 50) {
        if (!already.count("many_connections")) {
            sendAlert("T1071_many_connections", p);
            already.insert("many_connections");
        }
    }

    for (const auto& sn : {"systemd", "sshd", "cron", "init"}) {
        if (p.name == sn && p.exe.rfind("/tmp", 0) == 0) {
            if (!already.count("fake_sysprocess")) {
                sendAlert("T1036_masquerading", p);
                already.insert("fake_sysprocess");
            }
        }
    }

    if ((p.name == "python" || p.name == "python3" ||
         p.name == "perl"   || p.name == "ruby") &&
        p.cwd.rfind("/tmp", 0) == 0) {
        if (!already.count("script_in_tmp")) {
            sendAlert("T1059_script_in_tmp", p);
            already.insert("script_in_tmp");
        }
    }
}

int run_kdetect() {
    edr::log::init("kdetect");
    edr::log::info("surveillance comportementale active");

    std::map<int, std::set<std::string>> alerted;

    while (true) {
        for (int pid : listPids()) {
            try {
                ProcessInfo p = readProcess(pid);
                if (!p.name.empty())
                    checkRules(p, alerted);
            } catch (...) {}
        }

        for (auto it = alerted.begin(); it != alerted.end(); ) {
            if (!fs::exists("/proc/" + std::to_string(it->first)))
                it = alerted.erase(it);
            else
                ++it;
        }

        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    edr::log::shutdown();
    return 0;
}
