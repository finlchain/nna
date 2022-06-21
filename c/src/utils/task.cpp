/**
    @file task.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

pthread_t g_pthread_id[MAX_THREAD_NUM];
pid_t g_tid_nice[MAX_THREAD_NUM];

void task_set_pid_nice(void)
{
    int which = PRIO_PROCESS;
    id_t pid;
    int priority = 0;
     
    pid = getpid();
    setpriority(which, pid, priority);
}

void task_set_tid_nice(void)
{
    g_tid_nice[CLI_THREAD_IDX] = 0;
    g_tid_nice[RX_THREAD_IDX] = 0;
    g_tid_nice[TX_THREAD_IDX] = 0;
    g_tid_nice[P2P_THREAD_IDX] = 0;
    g_tid_nice[CONS_THREAD_IDX] = 0;
    g_tid_nice[DB_THREAD_IDX] = 0;
#if defined (USE_DB_REDIS)
    g_tid_nice[DB_REDIS_THREAD_IDX] = 0;
#endif // USE_DB_REDIS
}

