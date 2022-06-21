/**
    @file json_parse.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __JSON_PARSE_H__
#define __JSON_PARSE_H__

#ifdef __cplusplus
extern "C"
{
#endif

#define CFG_STR_SIZE        100
#define CFG_TMP_BUF_SIZE    CFG_STR_SIZE

#define CFG_NEXT_REVISION(a) ((a) + 1)

typedef struct
{
    char mreq_ip[IP_STR_SIZE];
    char ip[IP_STR_SIZE];
    int port;
    int auto_join;
    int p2p_join;
} CFG_SOCK_INFO_T;

//
extern uint32_t json_cons_rr_net_chk_ver(void);

//
extern void json_cons_rr_update(void);
extern void json_cons_udpate(void); // 4th updated
extern void json_p2p_udpate(void *pv_p2p_cntx); // 2nd updated
extern void json_socket_udpate(void *pv_sock_cntx); // 3rd updated
extern void json_node_info_update(void); // 1st updated
extern void json_reinit(void *pv_sock_cntx);

// 0: success,  else: db config file read fail or wrong format
extern int32_t json_db_update(void);

//
extern void json_cli_udpate(void *pv_cli_cntx);

#ifdef __cplusplus
}
#endif

#endif /* __JSON_PARSE_H__ */
