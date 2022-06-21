/**
    @file cons_rr.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/


#ifndef __CONS_RR_H__
#define __CONS_RR_H__

#ifdef __cplusplus
extern "C"
{
#endif

extern void cons_rr_net_init(void);
extern void cons_rr_subnet_init(void);

extern void cons_rr_net_set_blk_num(void);

extern void cons_rr_net_set_next_nn(void);

extern int32_t cons_tx_stop(void);

extern void cons_rr_init(void);
extern int32_t cons_rr_blk_gen_start(void);
extern int32_t cons_rr_blk_gen_stop(void);
extern int32_t cons_rr_chk_blk_gen_stop(void);
extern int32_t cons_rr_set_blk_gen_stop(CONS_BLK_GEN_STOP_E blk_gen_stop);

extern void cons_rr_geninfo_run(void);

#ifdef __cplusplus
}
#endif

#endif /* __CONS_RR_H__ */

