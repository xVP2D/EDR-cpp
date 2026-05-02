#ifndef RULES_HPP
#define RULES_HPP

#include "token.hpp"
#include <string>
#include <vector>

struct Pattern {
    std::string name;
    std::string value;
    TokenType   type;
};

class Rules {
private:
    std::vector<Token> _tokens;
    size_t _pos;

    bool eof() const { return _pos >= _tokens.size(); }
    Token peek() const { return eof() ? Token{TokenType::END_OF_FILE, ""} : _tokens[_pos]; }
    Token advance() { return _tokens[_pos++]; }

public:
    std::string name;
    std::vector<Pattern> patterns;
    std::string condition;

    Rules(const std::vector<Token>& tokens) : _tokens(tokens), _pos(0) {}

    void parse_rule() {
        advance();
        name = advance().value;
        advance();
        parse_strings();
        parse_condition();
        advance();
    }

    void parse_strings() {
        advance();
        advance();
        while (peek().type == TokenType::IDENTIFIER) {
            std::string id = advance().value;
            advance();
            Token val_tok  = advance();
            patterns.push_back({id, val_tok.value, val_tok.type});
        }
    }

    void parse_condition() {
        advance();
        advance();
        condition = "";
        while (!eof() && peek().type != TokenType::RBRACE) {
            condition += advance().value + " ";
        }
    }
};

#endif
