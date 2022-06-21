/**
    @file task_msg.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __TASK_MSG_H__
#define __TASK_MSG_H__

#ifdef __cplusplus
extern "C"
{
#endif

#define TASK_MSG_STATIC_BUF DISABLED // ENABLED DISABLED

#define TASK_MSG_POOL_SIZE 10000

#define TASK_BUF_SIZE 1536

typedef struct {
    LIST_ITEM_T link;
    uint32_t    event;
    uint32_t    len;
#if (TASK_MSG_STATIC_BUF == ENABLED)
    uint8_t     buf[TASK_BUF_SIZE];
#else
    uint8_t     *buf;
#endif // TASK_MSG_STATIC_BUF
}__attribute__((__packed__))  TASK_MSG_ITEM_T;

extern int32_t task_msg_init(LIST_T *p_list, LIST_T *p_pool, uint32_t pool_size, TASK_MSG_ITEM_T *p_item);
extern int32_t task_send_msg(LIST_T *p_pool, LIST_T *p_list, uint8_t *p_buf, int32_t len, uint32_t alloced, uint32_t event);
extern TASK_MSG_ITEM_T *task_get_msg(LIST_T *p_list);
extern void task_init_item(TASK_MSG_ITEM_T *p_item);
extern void task_clr_msg(LIST_T *p_pool, LIST_T *p_list, TASK_MSG_ITEM_T *p_item);

#ifdef __cplusplus
}
#endif

#endif /* __TASK_MSG_H__ */

