/**
    @file tx_task_msg.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __TX_TASK_MSG_H__
#define __TX_TASK_MSG_H__

#ifdef __cplusplus
extern "C"
{
#endif

#define TX_TASK_MSG_POOL_SIZE TASK_MSG_POOL_SIZE

#define TX_TASK_MSG_EVENT_01 1
#define TX_TASK_MSG_EVENT_02 2
#define TX_TASK_MSG_EVENT_03 3
#define TX_TASK_MSG_EVENT_04 4
#define TX_TASK_MSG_EVENT_05 5

#define TX_TASK_MSG_EVENT_06 6
#define TX_TASK_MSG_EVENT_07 7
#define TX_TASK_MSG_EVENT_08 8

extern LIST_T tx_task_list, tx_task_pool;
extern TASK_MSG_ITEM_T tx_task_items[TX_TASK_MSG_POOL_SIZE];

void tx_task_msg_init(void);
void tx_task_msg_handler(void);

#ifdef __cplusplus
}
#endif

#endif /* __TX_TASK_MSG_H__ */

