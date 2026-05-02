#ifndef TOKEN_HPP
#define TOKEN_HPP

#include <string>

enum class TokenType {
    RULE,
    STRINGS,
    CONDITION,
    IDENTIFIER,
    STRING_VAL,
    REGEX,
    HEX,
    LBRACE,
    RBRACE,
    COLON,
    EQUAL,
    END_OF_FILE,
    OR,
    AND,
    NOT,
    LPARENTHESE,
    RPARENTHESE
};

struct Token {
    TokenType type;
    std::string value;
};

#endif
