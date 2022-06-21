/**
    @file debug.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

#define DUMP_BUF_SIZE 84
#define DUMP_STR_SIZE 20
#define DUMP_COL_NUM  16

static uint32_t debug_module = DBG_UTIL |
                            DBG_SOCKET |
                            DBG_TIMER |
                            DBG_TASK |
                            DBG_LUA |
                            DBG_CLI |
                            DBG_SEC |
                            DBG_DB |
                            DBG_JSON |
                            DBG_MSGQ |
                            DBG_MQTT |
                            DBG_RX |
                            DBG_TX |
                            DBG_P2P |
                            DBG_CONS |
                            DBG_APP_RX |
                            DBG_APP_TX |
                            DBG_APP_SOCK |
                            DBG_APP;

static DBG_LEVEL_E debug_level = DBG_INFO;
static char debug_str_buf[DBG_BUF_SIZE];
static char debug_fd_str_buf[DBG_BUF_SIZE];
static char debug_color[DBG_END][DBG_COLOR_SIZE] 
                    = { COLOR_RESET, COLOR_ERROR, COLOR_WARN, COLOR_TRACE, COLOR_INFO, COLOR_NONE };

static const char dbg_lvl_char[DBG_END]  = {'C', 'E', 'W', 'T', 'I', 'N'};

static bool dbg_time_display = true;

pthread_mutex_t dbg_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t dump_mutex = PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t fd_dbg_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t fd_dump_mutex = PTHREAD_MUTEX_INITIALIZER;

void debug_init(bool b_time_display)
{
    int32_t release_mode = 1;

    //
    dbg_time_display = b_time_display;

    //
    release_mode = ATOI_M(RELEASE_MODE);    
    if(release_mode)
    {
        debug_level = DBG_WARN;
    }
    else
    {
        debug_level = DBG_INFO;
    }
}

int32_t debug_get_module(void)
{
    return (debug_module);
}

int32_t debug_get_level(void)
{
    return (debug_level);
}

void debug_printf (uint32_t module, DBG_LEVEL_E level, void *fmt, ...)
{
    if ((debug_module & module) && (debug_level >= level))
    {
        pthread_mutex_lock (&dbg_mutex);
        
        do
        {
            struct timeval curTime;
            char *p_buf;
            uint32_t len;

            len = 0;
            p_buf = debug_str_buf;
            MEMSET_M (p_buf, 0x00, DBG_BUF_SIZE);

            if (dbg_time_display)
            {
                gettimeofday (&curTime, NULL);
                
                sprintf (&p_buf[len], (char *)"[%ld:%06ld] ", curTime.tv_sec, curTime.tv_usec);
                len += STRLEN_M (p_buf);
            }
            
            sprintf (&p_buf[len], "%s", debug_color[level]);
            len += STRLEN_M (debug_color[level]);
            
            p_buf[len++] = '[';
            p_buf[len++] = dbg_lvl_char[level];
            p_buf[len++] = ']';
            p_buf[len++] = ' ';

            sprintf (&p_buf[len], "%s", debug_color[DBG_CLEAR]);
            len += STRLEN_M (debug_color[DBG_CLEAR]);

            do
            {
                va_list ap;
                
                va_start (ap, fmt);
                vsprintf (&p_buf[len], (char *)fmt, ap);
                va_end (ap);
                
            } while(0);

            printf ("%s", p_buf);
            //fprintf(stdout, "%s", p_buf);
            fflush(stdout);
        } while(0);

        pthread_mutex_unlock (&dbg_mutex);
    }
}

void debug_dump (uint32_t module, DBG_LEVEL_E level, void *str, const uint8_t *p_buf, uint32_t len)
{
    if ((debug_module & module) && (debug_level >= level))
    {
        DBG_PRINT (module, level, (void *)"%s, dump size = %d\n", (uint8_t *)str, len);
        
        pthread_mutex_lock(&dump_mutex);

        do
        {
            uint32_t cnt;
            char print_buf[DUMP_BUF_SIZE] ={0x00,}, str_buf[DUMP_STR_SIZE]={0x00,};

            for(cnt=0; cnt<len; cnt++)
            {
                if (cnt%DUMP_COL_NUM == 0)
                {
                    if (cnt != 0)
                    {
                        //strcat (print_buf, "\n");
                        printf ("%s\n", print_buf);
                        MEMSET_M(print_buf, 0x00, DUMP_BUF_SIZE);
                    }

                    sprintf (str_buf, "    %04d : ", cnt);
                    strcat (print_buf, str_buf);
                }

                sprintf (str_buf, "%02X ", p_buf[cnt]);
                strcat (print_buf, str_buf);
            }

            printf ("%s\n", print_buf);
            fflush(stdout);
        } while(0);
        
        pthread_mutex_unlock(&dump_mutex);
    } 
}

void debug_fd_printf (FILE *fp, uint32_t module, DBG_LEVEL_E level, void *fmt, ...)
{
    if ((debug_module & module) && (debug_level >= level))
    {
        pthread_mutex_lock (&fd_dbg_mutex);
        
        do
        {
            char *p_buf;
            uint32_t len;

            len = 0;
            p_buf = debug_fd_str_buf;
            MEMSET_M (p_buf, 0x00, DBG_BUF_SIZE);

            do
            {
                va_list ap;
                
                va_start (ap, fmt);
                vsprintf (&p_buf[len], (char *)fmt, ap);
                va_end (ap);
            } while(0);

            fprintf(fp, "%s", p_buf);
            fflush(fp);
        } while(0);

        pthread_mutex_unlock (&fd_dbg_mutex);
    }
}

void debug_fd_dump (FILE *fp, uint32_t module, DBG_LEVEL_E level, void *str, const uint8_t *p_buf, uint32_t len)
{
    if ((debug_module & module) && (debug_level >= level))
    {
        DBG_FD_PRINT (fp, module, level, (void *)"%s, dump size = %d\r\n", (uint8_t *)str, len);

        pthread_mutex_lock (&fd_dump_mutex);
        
        do
        {
            uint32_t cnt;
            char print_buf[DUMP_BUF_SIZE] ={0x00,}, str_buf[DUMP_STR_SIZE]={0x00,};
            
            for(cnt=0; cnt<len; cnt++)
            {
                if (cnt%DUMP_COL_NUM == 0)
                {
                    if (cnt != 0)
                    {
                        fprintf(fp, "%s\r\n", print_buf);
                        fflush(fp);
                        MEMSET_M(print_buf, 0x00, DUMP_BUF_SIZE);
                    }

                    sprintf (str_buf, "    %04d : ", (cnt));
                    strcat (print_buf, str_buf);
                }

                sprintf (str_buf, "%02X ", p_buf[cnt]);
                strcat (print_buf, str_buf);
            }

            //printf ("%s\n", print_buf);
            fprintf(fp, "%s\r\n", print_buf);
            fflush(fp);
        } while(0);
        
        pthread_mutex_unlock (&fd_dump_mutex);
    }
}


#if (DBG_CHK_DELAY_TIME == ENABLED)
void debug_delay_time(uint8_t *str, struct timespec *pt_start, struct timespec *pt_end, DBG_LEVEL_E level)
{
    DBG_PRINT(DBG_UTIL, level, (void *)"INFO: (%s) Diff time: %.5f sec \n", str, ((double)pt_end->tv_sec+1.0e-9*pt_end->tv_nsec)-((double)pt_start->tv_sec+1.0e-9*pt_start->tv_nsec));
}
#endif // DBG_CHK_DELAY_TIME

