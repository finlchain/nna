/**
    @file tx.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __TX_H__
#define __TX_H__

#ifdef __cplusplus
extern "C"
{
#endif

#define AUTO_TX_ON_RX_SIDE  ENABLED

#define TX_LEN_MAX 1300

typedef struct
{
    uint32_t cnt;
    uint8_t buf[TX_LEN_MAX];
} __attribute__((__packed__)) TX_FIELD_T;

typedef struct 
{
    //
} TX_CNTX_T;

extern TX_CNTX_T *tx_get_cntx(void);

extern void tx_task_init(void);
extern void *t_tx_main(void *p_data);

#ifdef __cplusplus
}
#endif

#endif /* __TX_H__ */

