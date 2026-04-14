#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <cstdlib>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>

std::vector<std::string> path_binary;

struct Pattern {
    std::string name;
    std::vector<unsigned char> bytes;
};

std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    std::vector<unsigned char> bytes;

    int i = 0;
    while (i + 1 < (int)hex.size()) {
        std::string one_byte = hex.substr(i, 2);
        int valeur = std::stoi(one_byte, nullptr, 16);
        unsigned char byte = (unsigned char)valeur;
        bytes.push_back(byte);
        i += 2;
    }

    return bytes;
}

std::vector<Pattern> load_patterns(const std::string& db_path) {
    std::vector<Pattern> patterns;
    std::ifstream file(db_path);
    std::string line;

    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }

        int position_sep = (int)line.find(':');

        if (position_sep == -1) {
            continue;
        }

        Pattern p;
        p.name = line.substr(0, position_sep);

        std::string partie_hex = line.substr(position_sep + 1);
        p.bytes = hex_to_bytes(partie_hex);

        if (!p.bytes.empty()) {
            patterns.push_back(p);
        }
    }

    return patterns;
}

void scan_binary(const std::string& bin_path, const std::vector<Pattern>& patterns) {
    std::ifstream file(bin_path, std::ios::binary);

    if (!file) {
        return;
    }

    std::vector<unsigned char> content;
    unsigned char byte;
    while (file.read((char*)&byte, 1)) {
        content.push_back(byte);
    }

    for (const auto& p : patterns) {
        auto it = std::search(
            content.begin(), content.end(),
            p.bytes.begin(),  p.bytes.end()
        );

        if (it != content.end()) {
            std::cout << "[ALERTE] " << bin_path
                      << " correspond au pattern : " << p.name
                      << std::endl;
        }
    }
}

bool is_executable(const std::string& path) {
    struct stat st;

    int resultat = stat(path.c_str(), &st);
    if (resultat != 0) {
        return false;
    }

    bool exec_proprietaire = st.st_mode & S_IXUSR;
    bool exec_groupe       = st.st_mode & S_IXGRP;
    bool exec_autres       = st.st_mode & S_IXOTH;

    return exec_proprietaire || exec_groupe || exec_autres;
}

std::vector<std::string> path_list() {
    std::string home = std::getenv("HOME"); 

    return {
        home + "/Downloads",
        home + "/Téléchargements",
        "/tmp",
        "/var/tmp",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/libexec",
        "/bin",
        "/sbin",
        home + "/.local/bin",
        "/opt",
        "/snap/bin",
        home + "/.npm-global/bin",
    };
}

int main() {
    bool monitor = true;
    char buffer[4096];

    std::vector<Pattern> patterns = load_patterns("pattern.db");

    int fd = inotify_init();

    std::map<int, std::string> wd_to_path;

    std::vector<std::string> dossiers = path_list();
    for (const auto& dossier : dossiers) {
        int wd = inotify_add_watch(fd, dossier.c_str(), IN_CREATE | IN_MODIFY | IN_MOVED_TO);
        if (wd >= 0) {
            wd_to_path[wd] = dossier;
        }
    }

    do {
        int len = read(fd, buffer, sizeof(buffer));

        int i = 0;
        while (i < len) {
            struct inotify_event* event = (struct inotify_event*)&buffer[i];

            if (event->len > 0) {
                std::string dossier        = wd_to_path[event->wd];
                std::string nom_fichier    = event->name;
                std::string chemin_complet = dossier + "/" + nom_fichier;

                if (is_executable(chemin_complet)) {

                    if (event->mask & IN_CREATE) {
                        std::cout << "[CREATE]  " << chemin_complet << std::endl;
                        path_binary.push_back(chemin_complet);
                        scan_binary(chemin_complet, patterns);
                    }

                    if (event->mask & IN_MODIFY) {
                        std::cout << "[MODIFY]  " << chemin_complet << std::endl;
                        path_binary.push_back(chemin_complet);
                        scan_binary(chemin_complet, patterns);
                    }

                    if (event->mask & IN_MOVED_TO) {
                        std::cout << "[INSTALL] " << chemin_complet << std::endl;
                        path_binary.push_back(chemin_complet);
                        scan_binary(chemin_complet, patterns);
                    }
                }
            }

            i += sizeof(struct inotify_event) + event->len;
        }

    } while (monitor);

    close(fd);
    return 0;
}