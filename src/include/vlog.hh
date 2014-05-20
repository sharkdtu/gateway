#ifndef VLOG_HH
#define VLOG_HH

#include "config.h"

#include <boost/noncopyable.hpp>
#include <string>
#include <sys/types.h>

#include <sys/socket.h>
#include <netdb.h>

namespace rusv
{

#define PRINTF_FORMAT(FMT, ARG1) __attribute__((__format__(printf, FMT, ARG1)))

struct Vlog_impl;

class Vlog : boost::noncopyable
{
public:
    /* Severity of a log message. */
    enum
	{
        LEVEL_EMER,
        LEVEL_ERR,
        LEVEL_WARN,
        LEVEL_INFO,
        LEVEL_DBG,
        N_LEVELS
    };
    typedef int Level;
    static const char* get_level_name(Level);
    static Level get_level_val(const char* name);

    /* Available destinations for log messages. */
    enum
	{
        FACILITY_SYSLOG,
        FACILITY_CONSOLE,
        //FACILITY_UDPSOCK,
        N_FACILITIES,
        ANY_FACILITY = -1
    };
    typedef int Facility;
    static const char* get_facility_name(Facility);
    static Facility get_facility_val(const char* name);

    /* Sources of log messages.
     *
     * Unlike levels and facilities, modules are dynamically 
	 * created at runtime. 
	 */
    typedef int Module;
    static const int ANY_MODULE = -1;
    const char* get_module_name(Module);

    Vlog();
    ~Vlog();

    /* Log level configuration. */
    void set_levels(Facility, Module, Level);
    std::string set_levels_from_string(const std::string&);
    std::string get_levels();

    /* Low-level logging functions. */
    bool is_loggable(Module, Level);
    Level min_loggable_level(Module);
    void output(Module, Level, const char*);

    /* Level caching. */
    void register_cache(Module, Level* cached_min_level);
    void unregister_cache(Level*);

private:
    Vlog_impl* pimpl;
    int hSock;
    struct sockaddr_in addr;
public:
    Module get_module_val(const char* name, bool create = true);

    /* High-level logging function. */
    void log(Module, Level, const char* format, ...) PRINTF_FORMAT(4, 5);
};

/* Singleton instance of Vlog. */
extern Vlog& vlog();

/*
 * Usage: declare a static instance of this type:
 *    static Vlog_module log("ctlpath");
 * and thereafter within that module you can easily and tersely output log
 * messages, like so:
 *    log.emer("NETWORK ON FIRE!");
 */
class Vlog_module
{
public:
    Vlog_module(const char* module_name);
    ~Vlog_module();

    bool is_emer_enabled()
    {
        return is_enabled(Vlog::LEVEL_EMER);
    }
    bool is_err_enabled()
    {
        return is_enabled(Vlog::LEVEL_ERR);
    }
    bool is_warn_enabled()
    {
        return is_enabled(Vlog::LEVEL_WARN);
    }
    bool is_info_enabled()
    {
        return is_enabled(Vlog::LEVEL_INFO);
    }
    bool is_dbg_enabled()
    {
        return is_enabled(Vlog::LEVEL_DBG);
    }
    bool is_enabled(Vlog::Level level)
    {
        return level <= cached_min_level;
    }

    void emer(const char* format, ...) PRINTF_FORMAT(2, 3);
    void err(const char* format, ...) PRINTF_FORMAT(2, 3);
    void warn(const char* format, ...) PRINTF_FORMAT(2, 3);
    void info(const char* format, ...) PRINTF_FORMAT(2, 3);
    void dbg(const char* format, ...) PRINTF_FORMAT(2, 3);
    void log(int level, const char* format, ...) PRINTF_FORMAT(3, 4);

    const Vlog::Module module;
private:
    mutable Vlog::Level cached_min_level;
};

/* Additional optimization for Vlog_module.
 *
 * In some situations, the overhead of evaluating and passing function
 * arguments to one of the Vlog_module logging functions may be significant
 * enough to want to avoid it when no log output will actually occur.  Using
 * one of these macros reduces the overhead to a single integer comparison.
 *
 * Declare a static instance of Vlog_module, as above, and then invoke one of
 * these macros as, e.g.
 *     VLOG_EMER(log, "NETWORK ON FIRE--BLAME %s!", user_name);
 */
#define VLOG(MODULE, LEVEL, ...)                \
    do {                                        \
        if ((MODULE).is_##LEVEL##_enabled()) {  \
            MODULE.LEVEL(__VA_ARGS__);          \
        }                                       \
    } while (0)
#define VLOG_EMER(MODULE, ...) VLOG(MODULE, emer, __VA_ARGS__)
#define VLOG_ERR(MODULE, ...) VLOG(MODULE, err, __VA_ARGS__)
#define VLOG_WARN(MODULE, ...) VLOG(MODULE, warn, __VA_ARGS__)
#define VLOG_INFO(MODULE, ...) VLOG(MODULE, info, __VA_ARGS__)
#define VLOG_DBG(MODULE, ...) VLOG(MODULE, dbg, __VA_ARGS__)

} // namespace rusv

#endif /* VLOG_HH */
