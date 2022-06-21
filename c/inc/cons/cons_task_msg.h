/**
    @file cons_task_msg.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __CONS_TASK_MSG_H__
#define __CONS_TASK_MSG_H__

#ifdef __cplusplus
extern "C"
{
#endif

#define CONS_TASK_MSG_POOL_SIZE TASK_MSG_POOL_SIZE

#define CONS_TASK_MSG_EVENT_01 1 // BGI Time is expired.
#define CONS_TASK_MSG_EVENT_02 2 // Transaction test
#define CONS_TASK_MSG_EVENT_03 3 // Consensus Confirm is expired.
#define CONS_TASK_MSG_EVENT_04 4
#define CONS_TASK_MSG_EVENT_05 5

#define CONS_TASK_MSG_EVENT_09 9 // Block Notification
#define CONS_TASK_MSG_EVENT_10 10 // Block Generation
#define CONS_TASK_MSG_EVENT_11 11 // FSdump generation
#define CONS_TASK_MSG_EVENT_12 12 // 
#define CONS_TASK_MSG_EVENT_13 13 // request stop receiving tx
#define CONS_TASK_MSG_EVENT_14 14

extern LIST_T cons_task_list, cons_task_pool;
extern TASK_MSG_ITEM_T cons_task_items[CONS_TASK_MSG_POOL_SIZE];

void cons_task_msg_init(void);
void cons_task_msg_handler(void);

#ifdef __cplusplus
}
#endif

#endif /* __CONS_TASK_MSG_H__ */

