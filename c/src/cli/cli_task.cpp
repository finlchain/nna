/**
    @file cli_task.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

void *t_cli_main(void *p_data)
{
    pid_t pid; // process id
    
    char* thread_name = (char*)p_data;
    int task_ret = TASK_EXIT_NORMAL;

#if (defined (_WIN32) || defined (_WIN64))
    pthread_t tid; // thread id
    
    pid = GetCurrentProcessId();
    tid = pthread_self();
#else
    pid_t tid;

    pid = getpid();
    tid = syscall(SYS_gettid);

    setpriority(PRIO_PROCESS, tid, g_tid_nice[CLI_THREAD_IDX]);
#endif

    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);
    DBG_PRINT(DBG_TX, DBG_INFO, (void *)"%s is started.! - pid(%d), tid(%d)\n", thread_name, pid, tid);

#if (CLI_SERIAL_EMULATOR == ENABLED)
    task_ret = cli_serial_emulator();
#endif // CLI_SERIAL_EMULATOR

    task_ret = cli_terminal();
    
    pthread_exit(&task_ret);

    return (void *)p_data;
}

void cli_task_init(void)
{
    cli_init();
}

