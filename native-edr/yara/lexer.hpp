#ifndef LEXER_HPP
#define LEXER_HPP

#include "token.hpp"
#include <iostream>
#include <string>
#include <vector>

class Lexer {
private:
    std::string _contenu;
    size_t _pos;

    bool eof() const { return _pos >= _contenu.size(); }
    char peek() const { return eof() ? '\0' : _contenu[_pos]; }
    char advance() { return _contenu[_pos++]; }

    Token lire_mot() {
        size_t debut = _pos;
        while (!eof() && (std::isalnum(peek()) || peek() == '_')) {
            advance();
        }
        std::string mot = _contenu.substr(debut, _pos - debut);

        if (mot == "rule")      return {TokenType::RULE, mot};
        if (mot == "strings")   return {TokenType::STRINGS, mot};
        if (mot == "condition") return {TokenType::CONDITION, mot};
        if (mot == "or")        return {TokenType::OR, mot};
        if (mot == "and")       return {TokenType::AND, mot};
        if (mot == "not")       return {TokenType::NOT, mot};
        return {TokenType::IDENTIFIER, mot};
    }

    Token lire_pattern_id() {
        advance();
        size_t debut = _pos;
        while (!eof() && (std::isalnum(peek()) || peek() == '_')) {
            advance();
        }
        return {TokenType::IDENTIFIER, "$" + _contenu.substr(debut, _pos - debut)};
    }

    Token lire_string() {
        advance();
        size_t debut = _pos;
        while (!eof() && peek() != '"') {
            advance();
        }
        std::string val = _contenu.substr(debut, _pos - debut);
        if (!eof()) advance();
        return {TokenType::STRING_VAL, val};
    }

    Token lire_regex() {
        advance();
        size_t debut = _pos;
        while (!eof() && peek() != '/') {
            if (peek() == '\\') {
                advance();
                if (!eof()) advance();
            } else advance();
        }
        if (eof()) {
            std::cout << "regex broken" << std::endl;
        }
        std::string val = _contenu.substr(debut, _pos - debut);
        if (!eof()) advance();
        return {TokenType::REGEX, val};
    }

    Token lire_hex() {
        advance();
        size_t debut = _pos;
        while (!eof() && peek() != '}') {
            advance();
        }
        std::string val = _contenu.substr(debut, _pos - debut);
        if (!eof()) advance();
        return {TokenType::HEX, val};
    }

public:
    Lexer(const std::string& contenu) : _contenu(contenu), _pos(0) {}

    std::vector<Token> tokenize() {
        std::vector<Token> tokens;

        while (!eof()) {
            char c = peek();

            if (std::isspace(static_cast<unsigned char>(c))) {
                advance();
                continue;
            }
            if (std::isalpha(static_cast<unsigned char>(c)) || c == '_') {
                tokens.push_back(lire_mot());
                continue;
            }
            if (c == '$') {
                tokens.push_back(lire_pattern_id());
                continue;
            }
            if (c == '"') {
                tokens.push_back(lire_string());
                continue;
            }
            if (c == '/') {
                tokens.push_back(lire_regex());
                continue;
            }
            if (c == '{') {
                if (!tokens.empty() && tokens.back().type == TokenType::EQUAL) {
                    tokens.push_back(lire_hex());
                } else {
                    advance();
                    tokens.push_back({TokenType::LBRACE, "{"});
                }
                continue;
            }
            if (c == '}') { advance(); tokens.push_back({TokenType::RBRACE, "}"}); continue; }
            if (c == ':') { advance(); tokens.push_back({TokenType::COLON, ":"}); continue; }
            if (c == '=') { advance(); tokens.push_back({TokenType::EQUAL, "="}); continue; }
            if (c == '(') { advance(); tokens.push_back({TokenType::LPARENTHESE, "("}); continue; }
            if (c == ')') { advance(); tokens.push_back({TokenType::RPARENTHESE, ")"}); continue; }

            advance();
        }

        tokens.push_back({TokenType::END_OF_FILE, ""});
        return tokens;
    }
};

#endif
