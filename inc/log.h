#pragma once

typedef enum {
    LOG_TRACE,
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
} log_level_t;

#define DEFAULT_LOG_LEVEL LOG_INFO

enum log_flag {
    LOG_NO_COLOR = 1 << 0,
    LOG_NO_TIME = 1 << 1
};

extern log_level_t _log_level;

/* Initialize logger */
void log_init(log_level_t level, int flags);

/* Parse log level from string */
int log_level_parse(const char* str, log_level_t* level);

/* Get string name of log level */
const char* log_level_str(log_level_t level);

void _log(log_level_t type, int print_errno, const char* file, int line, const char* format, ...);

#define LOG(level, err, format, args...)                          \
    do {                                                          \
        if (level >= _log_level) {                                \
            _log(level, err, __FILE__, __LINE__, format, ##args); \
        }                                                         \
    } while (0)

#ifndef NDEBUG
#define log_t(format, args...) LOG(LOG_TRACE, 0, format, ##args)
#define elog_t(format, args...) LOG(LOG_TRACE, 1, format, ##args)
#else
#define log_t(format, args...) ((void)0)
#define elog_t(format, args...) ((void)0)
#endif

#define log_d(format, args...) LOG(LOG_DEBUG, 0, format, ##args)
#define elog_d(format, args...) LOG(LOG_DEBUG, 1, format, ##args)

#define log_i(format, args...) LOG(LOG_INFO, 0, format, ##args)
#define elog_i(format, args...) LOG(LOG_INFO, 1, format, ##args)

#define log_w(format, args...) LOG(LOG_WARN, 0, format, ##args)
#define elog_w(format, args...) LOG(LOG_WARN, 1, format, ##args)

#define log_e(format, args...) LOG(LOG_ERROR, 0, format, ##args)
#define elog_e(format, args...) LOG(LOG_ERROR, 1, format, ##args)
