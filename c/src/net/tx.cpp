/**
    @file tx.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

TX_CNTX_T g_tx_cntx;

//pthread_mutex_t tx_mutex = PTHREAD_MUTEX_INITIALIZER;

static void tx_cntx_init(void)
{
    MEMSET_M(&g_tx_cntx, 0x00, sizeof(TX_CNTX_T));
}

TX_CNTX_T *tx_get_cntx(void)
{
    return (&g_tx_cntx);
}

void *t_tx_main(void *p_data)
{
    pid_t pid; // process id
    
    char* thread_name = (char*)p_data;
    bool exe_thread = true;
    int task_ret = TASK_EXIT_NORMAL;

#if (defined (_WIN32) || defined (_WIN64))
    pthread_t tid; // thread id
    
    pid = GetCurrentProcessId();
    tid = pthread_self();
#else
    pid_t tid;

    pid = getpid();
    tid = syscall(SYS_gettid);

    setpriority(PRIO_PROCESS, tid, g_tid_nice[TX_THREAD_IDX]);
#endif

    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);
    DBG_PRINT(DBG_TX, DBG_INFO, (void *)"%s is started.! - pid(%d), tid(%d)\n", thread_name, pid, tid);

    while (exe_thread)
    {
        tx_task_msg_handler();

        usleep(10);
    }

    pthread_exit(&task_ret);
    
    return (void *)p_data;
}

void tx_task_init(void)
{
    tx_cntx_init();

    tx_task_msg_init();
}

