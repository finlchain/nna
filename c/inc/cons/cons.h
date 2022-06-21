/**
    @file cons.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/


#ifndef __CONS_H__
#define __CONS_H__

#ifdef __cplusplus
extern "C"
{
#endif

// Test
extern bool cons_test_get_tx_rollback(void);
extern void cons_test_set_tx_rollback(bool tx_rollback);

//
extern void cons_update_prv_blk_info(CONS_LIGHT_BLK_T *p_prv_blk);
extern uint32_t cons_cal_blk_gen_interval(void);

//
extern void cons_set_prikey_enc(void);

//
extern int32_t cons_set_pubkey_dir(uint64_t peer_p2p_addr, char *p_pubkey_dir);
extern int32_t cons_pubkey_mkdir(char *p_pubkey_dir);
extern int32_t cons_pubkey_rmdir(char *p_pubkey_dir);
extern int32_t cons_set_pubkey_path(char *p_pubkey_dir, char *p_name, char *p_pubkey_path);
extern int32_t cons_pubkey_add(char *p_pubkey_path, uint8_t *p_pubkey);
extern int32_t cons_pubkey_del(char *p_pubkey_path);

// Cons Peer
extern CONS_PEER_T *cons_peer_set_nn(uint32_t peer_sock_fd, struct sockaddr_in *p_peer_sock_addr, uint64_t peer_p2p_addr);
extern int32_t cons_peer_del_nn(int32_t sockfd);
extern int32_t cons_peer_del_all(void);

// RR Network
extern CONS_GEN_INFO_T *cons_get_nxt_nn(uint64_t peer_p2p_addr);
extern int32_t cons_set_nxt_nn(int32_t peer_sock_fd, struct sockaddr_in *p_peer_sock_addr, uint64_t peer_p2p_addr);
extern int32_t cons_clr_nxt_nn(int32_t peer_sock_fd, struct sockaddr_in *p_peer_sock_addr, uint64_t peer_p2p_addr);

// 
extern int32_t cons_send_block_noti(uint32_t to_nn, CONS_LIGHT_BLK_T *p_light_blk, CONS_DBKEY_T *p_db_key_list);

// From SCA to NN DB
extern int32_t cons_send_tx(uint32_t tx_cnt, CONS_TX_INFO_T *p_tx_info);
extern int32_t cons_send_tx_ack (uint32_t result, uint64_t blk_num, uint32_t tx_cnt, CONS_TX_INFO_T *p_tx_info);

// Public Key
extern int32_t cons_set_my_pubkey(void);
extern int32_t cons_get_my_pubkey(uint8_t *p_pubkey);
extern int32_t cons_send_pubkey_noti(int32_t sockfd, uint8_t *p_dst_p2p_addr);

//
extern void cons_init(bool b_init);
extern CONS_CNTX_T *cons_get_cntx(void);

//
extern void cons_task_init(void);
extern void *t_cons_main(void *p_data);

#ifdef __cplusplus
}
#endif

#endif /* __CONS_H__ */

