/**
    @file cons_block.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

//
// GEN_BLOCK_DATA_SIZE = bn + p2p_addr + Block Generation Time + Previous Block Hash + TX count + TXs(tx1_dbkey | tx2_dbkey | ... + tx1_hash | tx2_hash | ... )
#define  GEN_BLOCK_DATA_SIZE        (BLK_NUM_SIZE + P2P_ADDR_LEN + BGT_SIZE + HASH_SIZE + BYTE_4 + (DB_KEY_SIZE + HASH_SIZE))
#define  COPY_AND_MOVE(D,I,S,L)     { MEMCPY_M((D+I), &(S), L); I += L; }

static int32_t cons_gen_block_hash(CONS_LIGHT_BLK_T *p_light_blk)
{
    int32_t ret = ERROR_;
    uint8_t total_tx[GEN_BLOCK_DATA_SIZE];

    DBG_PRINT(DBG_DB, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");

    do
    {
        uint32_t idx = 0;
        DB_TX_FIELD_T db_tx;

        // TXs
        db_tx.blk_num = p_light_blk->blk_num;
        DB_SELECT_XOR_TXS_F_BLK_TXS_W_BN(&db_tx);

        //
        COPY_AND_MOVE(total_tx, idx, p_light_blk->blk_num,  BLK_NUM_SIZE);
        COPY_AND_MOVE(total_tx, idx, p_light_blk->p2p_addr, P2P_ADDR_LEN);
        COPY_AND_MOVE(total_tx, idx, p_light_blk->bgt,      BGT_SIZE);
        COPY_AND_MOVE(total_tx, idx, p_light_blk->pbh,      HASH_SIZE);
        COPY_AND_MOVE(total_tx, idx, p_light_blk->tx_cnt,   BYTE_4);
        COPY_AND_MOVE(total_tx, idx, db_tx.db_key,          DB_KEY_SIZE);
        COPY_AND_MOVE(total_tx, idx, db_tx.sc_hash,         HASH_SIZE);

        //
        ASSERT_M(GEN_BLOCK_DATA_SIZE == idx);

        DBG_PRINT(DBG_DB, DBG_INFO, (void *)"data of block before hashing : size (%d)\n", idx);
        DBG_DUMP(DBG_DB, DBG_NONE, (void *)"data of block before hashing", (uint8_t *)total_tx, idx);

        // Hashing        
        openssl_sha256(p_light_blk->blk_hash, (uint8_t *)total_tx, GEN_BLOCK_DATA_SIZE);
        DBG_DUMP(DBG_DB, DBG_NONE, (void *)"new blk_hash : ", p_light_blk->blk_hash, HASH_SIZE);

        ret = SUCCESS_;
    } while(0);

    get_current_rss_monitor(DBG_NONE, (char *)"2");

    return (ret);
}

void cons_block_gen(void)
{
    int32_t ret = ERROR_;
    
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
    CONS_TIER_T *p_tier;
    P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();

    CONS_LIGHT_BLK_T light_blk;
    CONS_DBKEY_T *p_db_key_list;

    DBG_PRINT(DBG_CONS, DBG_TRACE, (void *)"(%s) - Start\n", __FUNCTION__);
    get_current_rss_monitor(DBG_WARN, (char *)"1");
    
    p_tier = &p_cons_cntx->net.tier[CONS_TIER_0];

    light_blk.blk_num = p_tier->blk_num;
    light_blk.p2p_addr = p_p2p_cntx->my_p2p_addr.u64;

    // get prvious block hash
    // read from db 
    if(p_tier->prv_blk_num == BLK_NUM_INIT_VAL)
    {
        MEMSET_M(light_blk.pbh, 0, HASH_SIZE);
    }
    else
    {
        MEMCPY_M(light_blk.pbh, p_tier->prv_blk_hash, HASH_SIZE);
        DBG_DUMP(DBG_CONS, DBG_NONE, (void *)"prv_blk_hash", p_tier->prv_blk_hash, HASH_SIZE);
    }
    
    // get tx_cnt
#if (REDIS_SUB_TX == DISABLED)
    DB_UPDATE_BN_T_BLK_TXS_W_BN0(light_blk.blk_num);
#endif // REDIS_SUB_TX

    light_blk.tx_cnt = DB_SELECT_COUNT_F_BLK_TXS_W_BN(light_blk.blk_num);

    DBG_PRINT(DBG_CONS, DBG_INFO, (void *)"blk_num(0x%016llX) my_tx_cnt(%d)\n", light_blk.blk_num, light_blk.tx_cnt);

    // generate block hash
    cons_gen_block_hash(&light_blk);

    if (p_cons_cntx->my_comp_pubkey[0] == CONS_GRP_HDR_SIG_ECDSA)
    {
        ret = openssl_ecdsa_sig(p_cons_cntx->b_enc_prikey, (char *)p_cons_cntx->my_prikey_path, light_blk.blk_hash, HASH_SIZE, (SSL_SIG_U *)light_blk.sig);
        ASSERT_M(ret == SUCCESS_);

        openssl_ecdsa_verify(light_blk.blk_hash, HASH_SIZE, (SSL_SIG_U *)light_blk.sig, &p_cons_cntx->my_comp_pubkey[0]);
    }
    else if (p_cons_cntx->my_comp_pubkey[0] == CONS_GRP_HDR_SIG_ED25519)
    {
        ret = openssl_ed25519_sig(p_cons_cntx->b_enc_prikey, (char *)p_cons_cntx->my_prikey_path, light_blk.blk_hash, HASH_SIZE, (SSL_SIG_U *)light_blk.sig);
        ASSERT_M(ret == SUCCESS_);

        DBG_DUMP(DBG_CONS, DBG_INFO, (void *)"my_comp_pubkey", &p_cons_cntx->my_comp_pubkey[1], ED25519_PUBLIC_KEY_LEN_);
        
        openssl_ed25519_verify(light_blk.blk_hash, HASH_SIZE, (SSL_SIG_U *)light_blk.sig, &p_cons_cntx->my_comp_pubkey[1]);
    }
    else
    {
        ASSERT_M(0);
    }

    MEMCPY_M(light_blk.sig_pubkey, p_cons_cntx->my_comp_pubkey, COMP_PUBKEY_SIZE);
    
    DBG_DUMP(DBG_CONS, DBG_NONE, (void *)"signature", light_blk.sig, SIG_SIZE);

    light_blk.bgt = util_curtime_ms();

    //
    p_db_key_list = (CONS_DBKEY_T *)MALLOC_M(sizeof(CONS_DBKEY_T));

    p_db_key_list->info.first_tx_db_key = DB_SELECT_1ST_DB_KEY_F_BLK_TXS_W_BN(light_blk.blk_num);
    p_db_key_list->info.last_tx_db_key = DB_SELECT_LAST_DB_KEY_F_BLK_TXS_W_BN(light_blk.blk_num);

    DBG_PRINT(DBG_CONS, DBG_INFO, (void *)"first dbkey(0x%016llX)\n", p_db_key_list->info.first_tx_db_key);
    DBG_PRINT(DBG_CONS, DBG_INFO, (void *)"last dbkey(0x%016llX)\n", p_db_key_list->info.last_tx_db_key);

    DBG_PRINT(DBG_CONS, DBG_WARN, (void *)"1 p2p_addr(0x%016llX), blk_num(0x%016llX), tx_cnt(%d) - success block gen\n", 
                                light_blk.p2p_addr, light_blk.blk_num, light_blk.tx_cnt);

    DBG_DUMP(DBG_CONS, DBG_NONE, (void *)"blk_hash", light_blk.blk_hash, HASH_SIZE);
    
    DB_INSERT_T_BLK_CONTENTS(&light_blk);

    // 
    p_tier->blk_gen_time = light_blk.bgt;
    cons_update_prv_blk_info(&light_blk);

    //
    cons_send_block_noti(true, &light_blk, p_db_key_list);

    FREE_M(p_db_key_list);

    get_current_rss_monitor(DBG_WARN, (char *)"2");
    DBG_PRINT(DBG_CONS, DBG_TRACE, (void *)"(%s) - End\n", __FUNCTION__);
}

int32_t cons_block_gen_msg(void)
{
    int32_t ret;
    
#if (CONS_TO_DB_TASK == ENABLED)
    ret = task_send_msg(&db_task_pool, &db_task_list, NULL, 0, false, DB_TASK_MSG_EVENT_03); // tier_id
#else
    ret = task_send_msg(&cons_task_pool, &cons_task_list, NULL, 0, false, CONS_TASK_MSG_EVENT_10); // tier_id
#endif // CONS_TO_DB_TASK
    if (ret == ERROR_)
    {
        ASSERT_M(0);
    }

    return (ret);
}

