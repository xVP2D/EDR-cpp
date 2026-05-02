#include "yara.hpp"
#include "lecture.hpp"
#include "lexer.hpp"
#include "condition.hpp"
#include "scanner.hpp"
#include "logging.hpp"

#include <filesystem>
#include <fstream>
#include <vector>
#include <thread>
#include <chrono>
#include <system_error>
#include <limits.h>
#include <unistd.h>

namespace fs = std::filesystem;

static std::string rules_dir() {
    char buf[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n < 0) return "yara/rules";
    buf[n] = '\0';
    return (fs::path(buf).parent_path() / "../yara/rules").lexically_normal().string();
}

static std::vector<Rules> load_rules(const std::string& dir) {
    std::vector<Rules> rules;
    if (!fs::exists(dir)) {
        edr::log::warn("dossier de regles introuvable: " + dir);
        return rules;
    }
    Lecture lecture;
    for (const auto& entry : fs::directory_iterator(dir)) {
        if (entry.path().extension() != ".yar") continue;
        std::string contenu = lecture.lecture_fichier(entry.path().string());
        if (contenu.empty()) continue;
        Lexer lexer(contenu);
        Rules rule(lexer.tokenize());
        rule.parse_rule();
        rules.push_back(rule);
        edr::log::info("regle chargee: " + rule.name);
    }
    return rules;
}

static std::string read_binary(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

int run_yara() {
    edr::log::init("yara");

    auto dir   = rules_dir();
    auto rules = load_rules(dir);
    edr::log::info(std::to_string(rules.size()) + " regles chargees");
    edr::log::info("surveillance de /tmp/edr_dump/");

    const std::string dump_dir = "/tmp/edr_dump";
    Scanner scanner;

    while (true) {
        if (!fs::exists(dump_dir)) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        for (const auto& entry : fs::directory_iterator(dump_dir)) {
            const std::string path = entry.path().string();

            std::string content = read_binary(path);
            if (content.empty()) continue;

            bool any_match = false;
            for (const auto& rule : rules) {
                if (scanner.scan(rule, content)) {
                    edr::log::warn("YARA MATCH rule=" + rule.name + " file=" + path);
                    any_match = true;
                }
            }

            if (!any_match)
                edr::log::info("propre file=" + path);

            std::error_code ec;
            fs::remove(path, ec);
            if (ec)
                edr::log::error("suppression echouee: " + path + " " + ec.message());
            else
                edr::log::info("supprime " + path);
        }

        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    edr::log::shutdown();
    return 0;
}
