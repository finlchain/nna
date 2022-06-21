/**
    @file task.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef _TASK_H__
#define _TASK_H__

#ifdef __cplusplus
extern "C"
{
#endif

#define MAX_THREAD_NUM  10

#define CLI_THREAD_IDX  0
#define RX_THREAD_IDX   1
#define TX_THREAD_IDX   2
#define P2P_THREAD_IDX  3
#define CONS_THREAD_IDX 4
#define DB_THREAD_IDX   5
#define DB_REDIS_THREAD_IDX   6
#define MQTT_THREAD_IDX 7

#define TASK_EXIT_ERROR         41
#define TASK_EXIT_NORMAL        42
#define TASK_EXIT_SERIAL_EMUL   43
#define TASK_EXIT_RX_RECV       44

extern pthread_t g_pthread_id[MAX_THREAD_NUM];
extern pid_t g_tid_nice[MAX_THREAD_NUM];

extern void task_set_pid_nice(void);
extern void task_set_tid_nice(void);

#ifdef __cplusplus
}
#endif

#endif /* _TASK_H__ */
