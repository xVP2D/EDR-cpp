#include "logging.hpp"

#include <fstream>
#include <mutex>
#include <chrono>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <ctime>

namespace edr::log {

namespace {
    std::ofstream g_file;
    std::mutex    g_mutex;

    std::string timestamp() {
        auto now  = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&time));
        return buf;
    }

    std::string_view level_str(Level lvl) {
        switch (lvl) {
            case Level::DEBUG: return "DEBUG";
            case Level::INFO:  return "INFO ";
            case Level::WARN:  return "WARN ";
            case Level::ERROR: return "ERROR";
        }
        return "?????";
    }
}

void init(std::string_view module_name) {
    const std::filesystem::path dir = "/var/log/naive-edr";
    std::filesystem::create_directories(dir);

    std::string path = std::string(dir) + "/" + std::string(module_name) + ".log";
    g_file.open(path, std::ios::app);

    if (!g_file.is_open())
        throw std::runtime_error("logging: cannot open " + path);

    info(std::string(module_name) + " started");
}

void shutdown() {
    std::lock_guard lock(g_mutex);
    if (g_file.is_open()) {
        g_file << "[" << timestamp() << "] INFO  === shutdown ===\n";
        g_file.close();
    }
}

void write(Level lvl, std::string_view msg) {
    std::lock_guard lock(g_mutex);
    g_file << "[" << timestamp() << "] " << level_str(lvl) << " " << msg << "\n";
    g_file.flush();
}

}