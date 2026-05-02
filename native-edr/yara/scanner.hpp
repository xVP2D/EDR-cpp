#pragma once
#include "condition.hpp"

#include <string>
#include <map>
#include <vector>
#include <sstream>
#include <regex>
#include <algorithm>
#include <cctype>

class Scanner {
public:
    bool scan(const Rules& rule, const std::string& content) {
        std::map<std::string, bool> results;
        for (const auto& p : rule.patterns)
            results[p.name] = match(p, content);
        return eval_condition(rule.condition, results);
    }

private:
    bool match(const Pattern& p, const std::string& content) {
        switch (p.type) {
            case TokenType::HEX:
                return content.find(hex_to_bytes(p.value)) != std::string::npos;
            case TokenType::REGEX: {
                try {
                    std::regex re(p.value);
                    return std::regex_search(content, re);
                } catch (...) { return false; }
            }
            default:
                return content.find(p.value) != std::string::npos;
        }
    }

    std::string hex_to_bytes(const std::string& hex) {
        std::string clean;
        for (char c : hex)
            if (std::isxdigit(static_cast<unsigned char>(c))) clean += c;
        if (clean.size() % 2 != 0) return "";
        std::string result;
        for (size_t i = 0; i < clean.size(); i += 2)
            result += static_cast<char>(std::stoi(clean.substr(i, 2), nullptr, 16));
        return result;
    }

    bool eval_condition(const std::string& cond,
                        const std::map<std::string, bool>& results) {
        if (cond.find("any") != std::string::npos)
            return std::any_of(results.begin(), results.end(),
                               [](const auto& p){ return p.second; });
        if (cond.find("all") != std::string::npos)
            return std::all_of(results.begin(), results.end(),
                               [](const auto& p){ return p.second; });

        std::istringstream iss(cond);
        std::vector<std::string> toks;
        for (std::string t; iss >> t; ) toks.push_back(t);
        if (toks.empty()) return false;

        bool result = eval_atom(toks, 0, results);
        size_t i = 1;
        while (i < toks.size()) {
            const std::string& op = toks[i++];
            if (op == "and" && i < toks.size())
                result = result && eval_atom(toks, i++, results);
            else if (op == "or" && i < toks.size())
                result = result || eval_atom(toks, i++, results);
        }
        return result;
    }

    bool eval_atom(const std::vector<std::string>& toks, size_t i,
                   const std::map<std::string, bool>& results) {
        if (i >= toks.size()) return false;
        if (toks[i] == "not" && i + 1 < toks.size())
            return !eval_atom(toks, i + 1, results);
        if (!toks[i].empty() && toks[i][0] == '$') {
            auto it = results.find(toks[i]);
            return it != results.end() && it->second;
        }
        return false;
    }
};
