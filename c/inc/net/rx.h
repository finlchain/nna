/**
    @file rx.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __RX_H__
#define __RX_H__

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct
{
    int32_t (*rx_evt_handle_cb)(void);
} __attribute__((__packed__)) RX_CBS_T;

extern void rx_task_init(void);
extern void *t_rx_main(void *p_data);

extern void rx_cb_set(RX_CBS_T *p_rx_cbs);

#ifdef __cplusplus
}
#endif

#endif /* __RX_H__ */

