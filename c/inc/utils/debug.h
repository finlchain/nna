/**
    @file debug.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __DEBUG_H__
#define __DEBUG_H__

#ifdef __cplusplus
extern "C"
{
#endif

#define DBG_CHK_DELAY_TIME ENABLED // ENABLED DISABLED

/* Definition of debug modules */
#define DBG_UTIL        (1 << 0)
#define DBG_SOCKET      (1 << 1)
#define DBG_TIMER       (1 << 2)
#define DBG_TASK        (1 << 3)
#define DBG_LUA         (1 << 4)
#define DBG_CLI         (1 << 5)
#define DBG_SEC         (1 << 6)
#define DBG_DB          (1 << 7)
#define DBG_JSON        (1 << 8)
#define DBG_MSGQ        (1 << 9)
#define DBG_MQTT        (1 << 10)

//
#define DBG_RX          (1 << 16)
#define DBG_TX          (1 << 17)
#define DBG_P2P         (1 << 18)
#define DBG_CONS        (1 << 19)

//
#define DBG_APP_RX      (1 << 28)
#define DBG_APP_TX      (1 << 29)
#define DBG_APP_SOCK    (1 << 30)
#define DBG_APP         (1 << 31)

#define COLOR_CLEAR "\x1b[0m"
#define COLOR_ERROR "\x1b[31m"  /* Red */
#define COLOR_WARN  "\x1b[32m"  /* Green */
#define COLOR_TRACE "\x1b[34m"  /* Blue */
#define COLOR_INFO  "\x1b[35m"  /* Magenta */
#define COLOR_NONE  "\x1b[36m"  /* Cyan */
#define COLOR_RESET "\x1b[0m"   /* All attributes off(color at startup) */

#define DBG_BUF_SIZE      4096
#define DBG_COLOR_SIZE    10

#define DBG_INIT  debug_init
#define DBG_PRINT debug_printf
#define DBG_DUMP  debug_dump
#define DBG_FD_PRINT debug_fd_printf
#define DBG_FD_DUMP debug_fd_dump

typedef enum {
    DBG_CLEAR = 0,
    DBG_ERROR,
    DBG_WARN,
    DBG_TRACE,
    DBG_INFO,
    DBG_NONE,
    DBG_END
} DBG_LEVEL_E;

void debug_init(bool b_time_display);
int32_t debug_get_module(void);
int32_t debug_get_level(void);
void debug_printf (uint32_t module, DBG_LEVEL_E level, void *fmt, ...);
void debug_dump (uint32_t module, DBG_LEVEL_E level, void *str, const uint8_t *p_buf, uint32_t len);
void debug_fd_printf (FILE *fp, uint32_t module, DBG_LEVEL_E level, void *fmt, ...);
void debug_fd_dump (FILE *fp, uint32_t module, DBG_LEVEL_E level, void *str, const uint8_t *p_buf, uint32_t len);

#if (DBG_CHK_DELAY_TIME == ENABLED)
void debug_delay_time(uint8_t *str, struct timespec *pt_start, struct timespec *pt_end, DBG_LEVEL_E level);
#endif // DBG_CHK_DELAY_TIME

#ifdef __cplusplus
}
#endif

#endif /* __DEBUG_H__ */

