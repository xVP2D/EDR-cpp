#ifndef LECTURE_HPP
#define LECTURE_HPP

#include <iostream>
#include <fstream>
#include <string>

class Lecture {
public:
    std::string lecture_fichier(const std::string& filename) {
        std::ifstream fichier(filename);

        if (!fichier.is_open()) {
            std::cerr << "Erreur : impossible d'ouvrir " << filename << std::endl;
            return "";
        }

        std::string contenu; //contenue vide
        std::string ligne;

        while (std::getline(fichier, ligne)) {
            contenu += ligne;
            contenu += "\n";
        }

        return contenu;
    }


};

#endif
