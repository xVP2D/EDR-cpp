#include <string_view>

namespace edr::log {

    enum class Level { DEBUG, INFO, WARN, ERROR };

    void init(std::string_view module_name);
    void shutdown();

    void write(Level lvl, std::string_view msg);

    inline void debug(std::string_view msg) { write(Level::DEBUG, msg); }
    inline void info (std::string_view msg) { write(Level::INFO,  msg); }
    inline void warn (std::string_view msg) { write(Level::WARN,  msg); }
    inline void error(std::string_view msg) { write(Level::ERROR, msg); }

}