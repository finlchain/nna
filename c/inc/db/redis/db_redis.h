/**
    @file db_redis.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __DB_REDIS_H__
#define __DB_REDIS_H__

#ifdef __cplusplus
extern "C"
{
#endif

#define REDIS_SUB_TX DISABLED // ENABLED DISABLED
#define REDIS_SUB_TX_NEW ENABLED // ENABLED DISABLED

#define REDIS_PUBSUB_CHECK DISABLED // ENABLED DISABLED

#define REDIS_PUBSUB_SUB_TX         0 // SUB from SCA
#define REDIS_PUBSUB_PUB_TX_ACK     1 // PUB to SCA
#define REDIS_PUBSUB_PUB_BLK_NOTI   2 // PUB to SCA
#define REDIS_PUBSUB_SUB_CTRL       3 // SUB from ISA
#define REDIS_PUBSUB_PUB_CTRL_ACKS  4 // PUB to ISA
#define REDIS_PUBSUB_MAX            5

#define REDIS_CHANNEL_NAME_MAX_LEN  20
#define REDIS_CONS_CMD_ARG_MAX      3

extern void *t_redis_main(void *p_data);
extern void redis_task_init(void);

// Publish to SCA
extern void redis_pub_tx_ack(CONS_TX_ACK_INFO_T *p_tx_ack);
extern void redis_pub_blk_noti(CONS_LIGHT_BLK_T* p_light_blk); 

// Publish to ISA
extern void redis_pub_ctrl_acks(const char *msg);
extern void redis_pub_ctrl_ack_node_start(void);

#ifdef __cplusplus
}
#endif

#endif /* __DB_REDIS_H__ */

