/**
    @file db_redis_task_msg.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __DB_REDIS_TASK_MSG_H__
#define __DB_REDIS_TASK_MSG_H__

#ifdef __cplusplus
extern "C"
{
#endif

#define DB_REDIS_TASK_MSG_POOL_SIZE TASK_MSG_POOL_SIZE

#define DB_REDIS_TASK_MSG_EVENT_01 1
#define DB_REDIS_TASK_MSG_EVENT_02 2
#define DB_REDIS_TASK_MSG_EVENT_03 3
#define DB_REDIS_TASK_MSG_EVENT_04 4

extern LIST_T db_redis_task_list, db_redis_task_pool;
extern TASK_MSG_ITEM_T db_redis_task_items[DB_REDIS_TASK_MSG_POOL_SIZE];

void db_redis_task_msg_init(void);
void db_redis_task_msg_handler(void);

#ifdef __cplusplus
}
#endif

#endif /* __DB_REDIS_TASK_MSG_H__ */

