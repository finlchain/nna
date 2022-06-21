/**
    @file p2p_task_msg.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __P2P_TASK_MSG_H__
#define __P2P_TASK_MSG_H__

#ifdef __cplusplus
extern "C"
{
#endif

#define P2P_TASK_MSG_POOL_SIZE TASK_MSG_POOL_SIZE

#define P2P_TASK_MSG_EVENT_01 1
#define P2P_TASK_MSG_EVENT_02 2
#define P2P_TASK_MSG_EVENT_03 3
#define P2P_TASK_MSG_EVENT_04 4
#define P2P_TASK_MSG_EVENT_05 5

extern LIST_T p2p_task_list, p2p_task_pool;
extern TASK_MSG_ITEM_T p2p_task_items[P2P_TASK_MSG_POOL_SIZE];

void p2p_task_msg_init(void);
void p2p_task_msg_handler(void);

#ifdef __cplusplus
}
#endif

#endif /* __P2P_TASK_MSG_H__ */

