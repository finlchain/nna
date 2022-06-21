/**
    @file rx.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

static RX_CBS_T g_rx_cbs;

void rx_cb_init(void)
{
    g_rx_cbs.rx_evt_handle_cb = NULL;
}

void rx_cb_set(RX_CBS_T *p_rx_cbs)
{
    if (p_rx_cbs)
    {
        if (p_rx_cbs->rx_evt_handle_cb)
        {
            g_rx_cbs.rx_evt_handle_cb = p_rx_cbs->rx_evt_handle_cb;
        }
    }
}

RX_CBS_T *rx_cb_get(void)
{
    return (&g_rx_cbs);
}

void *t_rx_main(void *p_data)
{
    pid_t pid; // process id
    
    char* thread_name = (char*)p_data;
    bool exe_thread = true;
    int task_ret = TASK_EXIT_NORMAL;
    int ret;
    RX_CBS_T *p_rx_cbs = rx_cb_get();

#if (defined (_WIN32) || defined (_WIN64))
    pthread_t tid; // thread id
    
    pid = GetCurrentProcessId();
    tid = pthread_self();
#else
    pid_t tid;

    pid = getpid();
    tid = syscall(SYS_gettid);

    setpriority(PRIO_PROCESS, tid, g_tid_nice[RX_THREAD_IDX]);
#endif

    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);
    DBG_PRINT(DBG_TX, DBG_INFO, (void *)"%s is started.! - pid(%d), tid(%d)\n", thread_name, pid, tid);

    while (exe_thread)
    {
        if (p_rx_cbs->rx_evt_handle_cb)
        {
            ret = p_rx_cbs->rx_evt_handle_cb();
            if (ret == ERROR_)
            {
                task_ret = TASK_EXIT_RX_RECV;
                break;
            }
        }
		
        usleep(10);
    }

    pthread_exit(&task_ret);

    return (void *)p_data;
}

void rx_task_init(void)
{
    rx_cb_init();
}

