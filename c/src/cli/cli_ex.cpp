/**
    @file cli_ex.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

// ROOT
extern void cli_help(FILE *fp, uint32_t argc, const char **argv);

// ROOT EMULATOR
extern void cli_emul(FILE *fp, uint32_t argc, const char **argv);
extern void cli_emul_help(FILE *fp, uint32_t argc, const char **argv);
extern void cli_emul_run(FILE *fp, uint32_t argc, const char **argv);


// ROOT CLI
extern void cli_cli(FILE *fp, uint32_t argc, const char **argv);
extern void cli_cli_help(FILE *fp, uint32_t argc, const char **argv);
extern void cli_cli_history(FILE *fp, uint32_t argc, const char **argv);
extern void cli_cli_pre_cmd(FILE *fp, uint32_t argc, const char **argv);

// ROOT NET
extern void cli_net(FILE *fp, uint32_t argc, const char **argv);
extern void cli_net_help(FILE *fp, uint32_t argc, const char **argv);
extern void cli_net_onepass(FILE *fp, uint32_t argc, const char **argv);
extern void cli_net_reinit(FILE *fp, uint32_t argc, const char **argv);
extern void cli_net_rerun(FILE *fp, uint32_t argc, const char **argv);
extern void cli_net_rrinit(FILE *fp, uint32_t argc, const char **argv);
extern void cli_net_rrupdate(FILE *fp, uint32_t argc, const char **argv);
extern void cli_net_rrnext(FILE *fp, uint32_t argc, const char **argv);
extern void cli_net_blkstart(FILE *fp, uint32_t argc, const char **argv);
extern void cli_net_blkstop(FILE *fp, uint32_t argc, const char **argv);
extern void cli_net_dumpstart(FILE *fp, uint32_t argc, const char **argv);
extern void cli_net_dumpstop(FILE *fp, uint32_t argc, const char **argv);

// ROOT DB
extern void cli_db(FILE *fp, uint32_t argc, const char **argv);
extern void cli_db_help(FILE *fp, uint32_t argc, const char **argv);
extern void cli_db_truncate(FILE *fp, uint32_t argc, const char **argv);
extern void cli_db_lastbn(FILE *fp, uint32_t argc, const char **argv);

// ROOT DB SC
extern void cli_db_sc(FILE *fp, uint32_t argc, const char **argv);
extern void cli_db_sc_help(FILE *fp, uint32_t argc, const char **argv);
extern void cli_db_sc_truncate(FILE *fp, uint32_t argc, const char **argv);

// ROOT DB BLOCK
extern void cli_db_block(FILE *fp, uint32_t argc, const char **argv);
extern void cli_db_block_help(FILE *fp, uint32_t argc, const char **argv);
extern void cli_db_block_truncate(FILE *fp, uint32_t argc, const char **argv);

// ROOT TEST
extern void cli_test(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_help(FILE *fp, uint32_t argc, const char **argv);

// ROOT TEST CRYPTO
extern void cli_test_crypto(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_crypto_help(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_crypto_kdf2(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_crypto_base58(FILE *fp, uint32_t argc, const char **argv);

// ROOT TEST EC
extern void cli_test_ec(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_ec_help(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_ec_gen(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_ec_ecdsa(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_ec_ecies(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_ec_verify(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_ec_pkcomp(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_ec_pkdecomp(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_ec_pem2hex(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_ec_hex2pem(FILE *fp, uint32_t argc, const char **argv);

// ROOT TEST ED
extern void cli_test_ed(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_ed_help(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_ed_edgen(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_ed_ed25519(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_ed_edtest(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_ed_xgen(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_ed_xkeytest(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_ed_x25519(FILE *fp, uint32_t argc, const char **argv);

// ROOT TEST RSA
extern void cli_test_rsa(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_rsa_help(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_rsa_gen(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_rsa_encdec(FILE *fp, uint32_t argc, const char **argv);

// ROOT TEST HASH
extern void cli_test_hash(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_hash_help(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_hash_sha256(FILE *fp, uint32_t argc, const char **argv);

// ROOT TEST AES
extern void cli_test_aes(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_aes_help(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_aes_cbc(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_aes_pwenc(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_aes_pwdec(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_aes_ecprvenc(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_aes_ecprvdec(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_aes_edprvenc(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_aes_edprvdec(FILE *fp, uint32_t argc, const char **argv);

// ROOT TEST HSM
extern void cli_test_hsm(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_hsm_help(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_hsm_yubihsm(FILE *fp, uint32_t argc, const char **argv);

// ROOT TEST DB
extern void cli_test_db(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_db_help(FILE *fp, uint32_t argc, const char **argv);

#if defined(USE_MYSQL)
// ROOT TEST DB MYSQL
extern void cli_test_db_mysql(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_db_mysql_help(FILE *fp, uint32_t argc, const char **argv);
#endif // USE_MYSQL

#if defined(USE_MONGODB)
// ROOT TEST DB MONGO
extern void cli_test_db_mongo(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_db_mongo_help(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_db_mongo_init(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_db_mongo_truncate(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_db_mongo_tx(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_db_mongo_tx_bulk(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_db_mongo_tx_update(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_db_mongo_block(FILE *fp, uint32_t argc, const char **argv);
#endif // USE_MONGODB

// ROOT TEST DB REDIS
extern void cli_test_db_redis(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_db_redis_help(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_db_redis_test(FILE *fp, uint32_t argc, const char **argv);

// ROOT TEST MSG
extern void cli_test_msg(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_msg_help(FILE *fp, uint32_t argc, const char **argv);

// ROOT TEST TIMER
extern void cli_test_timer(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_timer_help(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_timer_trace(FILE *fp, uint32_t argc, const char **argv);

// ROOT TEST UTIL
extern void cli_test_util(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_util_help(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_util_crc32(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_util_crc32a(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_util_crc32b(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_util_slice(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_util_sysinfo(FILE *fp, uint32_t argc, const char **argv);
extern void cli_test_util_jsonc(FILE *fp, uint32_t argc, const char **argv);

// 
static const char cli_help_msg[] = {
    "CLI v0.0\n"
    "Commands:\n"};

// ROOT
static const cli_func_t cli_root_func[] = {
    {"help", cli_help, "help"},
    {"emul", cli_emul, "emul"},
    {"cli", cli_cli, "cli"},
    {"net", cli_net, "net"},
    {"db", cli_db, "db"},
    {"test", cli_test, "test"},
    {NULL, NULL, NULL}};

// ROOT EMULATOR
static const cli_func_t cli_emul_func[] = {
    {"help", cli_emul_help, "emul help"},
    {"run", cli_emul_run, "run"},
    {NULL, NULL, NULL}};

// ROOT CLI
static const cli_func_t cli_cli_func[] = {
    {"help", cli_cli_help, "log help"},
    {"history", cli_cli_history, "history"},
    {"!", cli_cli_pre_cmd, "!"},
    {NULL, NULL, NULL}};

// ROOT NET
static const cli_func_t cli_net_func[] = {
    {"help", cli_net_help, "net help"},
    {"onepass", cli_net_onepass, "onepass"},
    {"reinit", cli_net_reinit, "reinit"},
    {"rerun", cli_net_rerun, "rerun"},
    {"rrinit", cli_net_rrinit, "rrinit"},
    {"rrupdate", cli_net_rrupdate, "rrupdate"},
    {"rrnext", cli_net_rrnext, "rrnext"},
    {"blkstart", cli_net_blkstart, "blkstart"},
    {"blkstop", cli_net_blkstop, "blkstop"},
    {"dumpstart", cli_net_dumpstart, "dumpstart"},
    {"dumpstop", cli_net_dumpstop, "dumpstop"},
    {NULL, NULL, NULL}};

// ROOT DB
static const cli_func_t cli_db_func[] = {
    {"help", cli_db_help, "db help"},
    {"truncate", cli_db_truncate, "truncate"},
    {"lastbn", cli_db_lastbn, "lastbn"},
    //
    {"sc", cli_db_sc, "sc"},
    {"block", cli_db_block, "block"},
    {NULL, NULL, NULL}};

// ROOT DB SC
static const cli_func_t cli_db_sc_func[] = {
    {"help", cli_db_sc_help, "sc help"},
    {"truncate", cli_db_sc_truncate, "truncate"},
    {NULL, NULL, NULL}};

// ROOT DB BLOCK
static const cli_func_t cli_db_block_func[] = {
    {"help", cli_db_block_help, "sc help"},
    {"truncate", cli_db_block_truncate, "truncate"},
    {NULL, NULL, NULL}};

// ROOT TEST
static const cli_func_t cli_test_func[] = {
    {"help", cli_test_help, "test help"},
    {"crypto", cli_test_crypto, "crypto"},
    {"ec", cli_test_ec, "ec"},
    {"ed", cli_test_ed, "ed"},
    {"rsa", cli_test_rsa, "rsa"},
    {"hash", cli_test_hash, "hash"},
    {"aes", cli_test_aes, "aes"},
    {"hsm", cli_test_hsm, "hsm"},
    {"db", cli_test_db, "db"},
    {"msg", cli_test_msg, "msg"},
    {"timer", cli_test_timer, "timer"},
    {"util", cli_test_util, "util"},
    {NULL, NULL, NULL}};

// ROOT TEST CRYPTO
static const cli_func_t cli_test_crypto_func[] = {
    {"help", cli_test_crypto_help, "crypto help"},
    {"kdf2", cli_test_crypto_kdf2, "kdf2"},
    {"base58", cli_test_crypto_base58, "base58"},
    {NULL, NULL, NULL}};

// ROOT TEST EC
static const cli_func_t cli_test_ec_func[] = {
    {"help", cli_test_ec_help, "ec help"},
    {"gen", cli_test_ec_gen, "gen"},
    {"ecdsa", cli_test_ec_ecdsa, "ecdsa"},

    {"ecies", cli_test_ec_ecies, "ecies"},
    {"verify", cli_test_ec_verify, "verify"},
    {"pkcomp", cli_test_ec_pkcomp, "pkcomp"},

    {"pkdecomp", cli_test_ec_pkdecomp, "pkdecomp"},
    {"pem2hex", cli_test_ec_pem2hex, "pem2hex"},

    {"hex2pem", cli_test_ec_hex2pem, "hex2pem"},
    {NULL, NULL, NULL}};

// ROOT TEST ED
static const cli_func_t cli_test_ed_func[] = {
    {"help", cli_test_ed_help, "ed help"},
    {"edgen", cli_test_ed_edgen, "edgen"},
    {"ed25519", cli_test_ed_ed25519, "ed25519"},
    {"edtest", cli_test_ed_edtest, "edtest"},
    {"xgen", cli_test_ed_xgen, "xgen"},
    {"xkeytest", cli_test_ed_xkeytest, "xkeytest"},
    {"x25519", cli_test_ed_x25519, "x25519"},
    {NULL, NULL, NULL}};

// ROOT TEST RSA
static const cli_func_t cli_test_rsa_func[] = {
    {"help", cli_test_rsa_help, "rsa help"},
    {"gen", cli_test_rsa_gen, "gen"},
    {"encdec", cli_test_rsa_encdec, "encdec"},
    {NULL, NULL, NULL}};

// ROOT TEST HASH
static const cli_func_t cli_test_hash_func[] = {
    {"help", cli_test_hash_help, "hash help"},
    {"sha256", cli_test_hash_sha256, "sha256"},
    {NULL, NULL, NULL}};

// ROOT TEST AES
static const cli_func_t cli_test_aes_func[] = {
    {"help", cli_test_aes_help, "aes help"},
    {"cbc", cli_test_aes_cbc, "cbc"},
    {"pwenc", cli_test_aes_pwenc, "pwenc"},
    {"pwdec", cli_test_aes_pwdec, "pwdec"},
    {"ecprvenc", cli_test_aes_ecprvenc, "ecprvenc"},
    {"ecprvdec", cli_test_aes_ecprvdec, "ecprvdec"},
    {"edprvenc", cli_test_aes_edprvenc, "edprvenc"},
    {"edprvdec", cli_test_aes_edprvdec, "edprvdec"},
    {NULL, NULL, NULL}};

// ROOT TEST HSM
static const cli_func_t cli_test_hsm_func[] = {
    {"help", cli_test_hsm_help, "hsm help"},
    {"yubihsm", cli_test_hsm_yubihsm, "yubihsm"},
    {NULL, NULL, NULL}};

// ROOT TEST DB
static const cli_func_t cli_test_db_func[] = {
    {"help", cli_test_db_help, "DB help"},
#if defined(USE_MYSQL)
    {"mysql", cli_test_db_mysql, "mysql"},
#endif // USE_MYSQL
#if defined(USE_MONGODB)
    {"mongo", cli_test_db_mongo, "mongo"},
#endif // USE_MONGODB
    {"redis", cli_test_db_redis, "redis"},
    {NULL, NULL, NULL}};

#if defined(USE_MYSQL)
// ROOT TEST DB MYSQL
static const cli_func_t cli_test_db_mysql_func[] = {
    {"help", cli_test_db_mysql_help, "mysql help"},
    {NULL, NULL, NULL}};
#endif // USE_MYSQL

#if defined(USE_MONGODB)
// ROOT TEST DB MONGO
static const cli_func_t cli_test_db_mongo_func[] = {
    {"help", cli_test_db_mongo_help, "mongodb help"},
    {"init", cli_test_db_mongo_init, "init"},
    {"truncate", cli_test_db_mongo_truncate, "truncate"},
    {"tx", cli_test_db_mongo_tx, "tx"},
    {"txbulk", cli_test_db_mongo_tx_bulk, "txbulk"},
    {"txupdate", cli_test_db_mongo_tx_update, "txupdate"},
    {"block", cli_test_db_mongo_block, "block"},
    {NULL, NULL, NULL}};
#endif // USE_MONGODB

// ROOT TEST DB REDIS
static const cli_func_t cli_test_db_redis_func[] = {
    {"help", cli_test_db_redis_help, "redis help"},
    {"init", cli_test_db_redis_test, "init"},
    {NULL, NULL, NULL}};

// ROOT TEST MSG
static const cli_func_t cli_test_msg_func[] = {
    {"help", cli_test_msg_help, "msg help"},
    {NULL, NULL, NULL}};

// ROOT TEST TIMER
static const cli_func_t cli_test_timer_func[] = {
    {"help", cli_test_timer_help, "timer help"},
    {"trace", cli_test_timer_trace, "trace"},
    {NULL, NULL, NULL}};


// ROOT TEST UTIL
static const cli_func_t cli_test_util_func[] = {
    {"help", cli_test_util_help, "util help"},
    {"crc32", cli_test_util_crc32, "crc32"},
    {"crc32a", cli_test_util_crc32a, "crc32a"},
    {"crc32b", cli_test_util_crc32b, "crc32b"},
    {"slice", cli_test_util_slice, "slice"},
    {"sysinfo", cli_test_util_sysinfo, "sysinfo"},
    {"jsonc", cli_test_util_jsonc, "jsonc"},
    {NULL, NULL, NULL}};

static int cli_utils_print(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    int n = vfprintf(stdout, fmt, args);
    va_end(args);

    return n;
}

// ROOT HELP
void cli_help(FILE *fp, uint32_t argc, const char **argv)
{
    cli_utils_print(cli_help_msg);
    
    // traverse through all available functions and print "command + description"
    for (const cli_func_t *ptr = cli_root_func; ptr->p_cmd != NULL; ++ptr)
    {
        cli_utils_print(" - %s\t-\t%s\n", ptr->p_cmd, ptr->p_func_desc);
    }
}

// ROOT EMULATOR
void cli_emul(FILE *fp, uint32_t argc, const char **argv)
{
    if (argc)
    {
        for (const cli_func_t *ptr = cli_emul_func; ptr->p_cmd != NULL; ++ptr)
        {
            if(STRCMP_M( argv[0], ptr->p_cmd) == 0)
            {
                ptr->cli_handler(fp, argc-1, (const char **)&argv[1]);
                break;
            }
        }
    }
    else
    {
        DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO,(void*)"%s\n", __FUNCTION__);
    }
}

void cli_emul_help(FILE *fp, uint32_t argc, const char **argv)
{
    for (const cli_func_t *ptr = cli_emul_func; ptr->p_cmd != NULL; ++ptr)
    {
        cli_utils_print(" - %s\t-\t%s\n", ptr->p_cmd, ptr->p_func_desc);
    }
}

void cli_emul_run(FILE *fp, uint32_t argc, const char **argv)
{
#if (CLI_SERIAL_EMULATOR == ENABLED)
    cli_serial_emulator();
#else
    DBG_FD_PRINT(fp, DBG_CLI, DBG_ERROR,(void*)"Serial Emulator is NOT supported.\n");
#endif // CLI_SERIAL_EMULATOR
}

// ROOT CLI
void cli_cli(FILE *fp, uint32_t argc, const char **argv)
{
    if (argc)
    {
        for (const cli_func_t *ptr = cli_cli_func; ptr->p_cmd != NULL; ++ptr)
        {
            if(STRCMP_M( argv[0], ptr->p_cmd) == 0)
            {
                ptr->cli_handler(fp, argc-1, (const char **)&argv[1]);
                break;
            }
        }
    }
    else
    {
        DBG_PRINT(DBG_CLI, DBG_INFO,(void*)"%s\n", __FUNCTION__);
    }
}

void cli_cli_help(FILE *fp, uint32_t argc, const char **argv)
{
    for (const cli_func_t *ptr = cli_cli_func; ptr->p_cmd != NULL; ++ptr)
    {
        cli_utils_print(" - %s\t-\t%s\n", ptr->p_cmd, ptr->p_func_desc);
    }
}

void cli_cli_history(FILE *fp, uint32_t argc, const char **argv)
{
    cli_get_log_history(fp);
}

void cli_cli_pre_cmd(FILE *fp, uint32_t argc, const char **argv)
{
    cli_exe_last_log(fp);
}


// ROOT NET
void cli_net(FILE *fp, uint32_t argc, const char **argv)
{
    if (argc)
    {
        for (const cli_func_t *ptr = cli_net_func; ptr->p_cmd != NULL; ++ptr)
        {
            if(STRCMP_M( argv[0], ptr->p_cmd) == 0)
            {
                ptr->cli_handler(fp, argc-1, (const char **)&argv[1]);
                break;
            }
        }
    }
    else
    {
        DBG_PRINT(DBG_CLI, DBG_INFO,(void*)"%s\n", __FUNCTION__);
    }
}

void cli_net_help(FILE *fp, uint32_t argc, const char **argv)
{
    for (const cli_func_t *ptr = cli_net_func; ptr->p_cmd != NULL; ++ptr)
    {
        cli_utils_print(" - %s\t-\t%s\n", ptr->p_cmd, ptr->p_func_desc);
    }
}

void cli_net_onepass(FILE *fp, uint32_t argc, const char **argv)
{
    cons_rr_geninfo_run();
}

void cli_net_reinit(FILE *fp, uint32_t argc, const char **argv)
{
    // Remove node.json, rr_net.json, rr_subnet.json
    json_reinit(p2p_sock_cntx());
}

void cli_net_rerun(FILE *fp, uint32_t argc, const char **argv)
{
    // Parse node.json
    p2p_init(false);
    cons_init(false);
}

void cli_net_rrinit(FILE *fp, uint32_t argc, const char **argv)
{
    cons_rr_init();
}

void cli_net_rrupdate(FILE *fp, uint32_t argc, const char **argv)
{
    json_cons_rr_update();
}

void cli_net_rrnext(FILE *fp, uint32_t argc, const char **argv)
{
    cons_rr_net_set_next_nn();
}

void cli_net_blkstart(FILE *fp, uint32_t argc, const char **argv)
{
    cons_rr_blk_gen_start();
}

void cli_net_blkstop(FILE *fp, uint32_t argc, const char **argv)
{
    cons_rr_set_blk_gen_stop(CONS_BLK_GEN_STOP_BY_SELF);
}

void cli_net_dumpstart(FILE *fp, uint32_t argc, const char **argv)
{
    int32_t tm_usec;
    
    if(!argc)
    {
        DBG_FD_PRINT(fp, DBG_CLI, DBG_ERROR, (void *)"Error : argc(%d)\r\n", argc);
        return;
    }
    
    tm_usec = ATOI_M(argv[0]);
    
    DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO, (void *)"fsdump start.!!! - tm_usec : %d\r\n", tm_usec);
    
    if (tm_usec)
    {
        cons_test_set_tx_rollback(false);
        
        if (cons_test_get_tx_rollback() == false)
        {
            timer_sw_dereg_by_name((uint8_t *)"fsdump");
            timer_sw_reg((uint8_t *)"fsdump", false, tm_usec, 0, cons_fsdump_temp,0);
        }
        else
        {
            DBG_FD_PRINT(fp, DBG_CLI, DBG_ERROR, (void *)"Error - tx_rollback is turned on.\r\n");
        }
    }
    else
    {
        cons_test_set_tx_rollback(true);
        
        cons_fsdump_temp(0);
    }

}

void cli_net_dumpstop(FILE *fp, uint32_t argc, const char **argv)
{
    DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO, (void *)"fsdump stop.!!!\r\n");
    
    cons_test_set_tx_rollback(false);
    timer_sw_dereg_by_name((uint8_t *)"fsdump");
}

// ROOT DB
void cli_db(FILE *fp, uint32_t argc, const char **argv)
{
    if (argc)
    {
        for (const cli_func_t *ptr = cli_db_func; ptr->p_cmd != NULL; ++ptr)
        {
            if(STRCMP_M( argv[0], ptr->p_cmd) == 0)
            {
                ptr->cli_handler(fp, argc-1, (const char **)&argv[1]);
                break;
            }
        }
    }
    else
    {
        DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO,(void*)"%s\n", __FUNCTION__);
    }
}

void cli_db_help(FILE *fp, uint32_t argc, const char **argv)
{
    for (const cli_func_t *ptr = cli_db_func; ptr->p_cmd != NULL; ++ptr)
    {
        cli_utils_print(" - %s\t-\t%s\n", ptr->p_cmd, ptr->p_func_desc);
    }
}

void cli_db_truncate(FILE *fp, uint32_t argc, const char **argv)
{
    DB_TRUNCATE();
}

void cli_db_lastbn(FILE *fp, uint32_t argc, const char **argv)
{
    uint64_t last_blk_num;
    
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
    CONS_TIER_T *p_tier;

    last_blk_num = DB_SELECT_LAST_BN_F_BLK_CONTENTS();
    
    p_tier = &p_cons_cntx->net.tier[CONS_TIER_0];
    
    p_tier->blk_num = last_blk_num;
    
    DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO, (void *)"Update blk_num(0x%016llX).\n", p_tier->blk_num);
}

// ROOT DB SC
void cli_db_sc(FILE *fp, uint32_t argc, const char **argv)
{
    if (argc)
    {
        for (const cli_func_t *ptr = cli_db_sc_func; ptr->p_cmd != NULL; ++ptr)
        {
            if(STRCMP_M( argv[0], ptr->p_cmd) == 0)
            {
                ptr->cli_handler(fp, argc-1, (const char **)&argv[1]);
                break;
            }
        }
    }
    else
    {
        DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO,(void*)"%s\n", __FUNCTION__);
    }
}

void cli_db_sc_help(FILE *fp, uint32_t argc, const char **argv)
{
    for (const cli_func_t *ptr = cli_db_sc_func; ptr->p_cmd != NULL; ++ptr)
    {
        cli_utils_print(" - %s\t-\t%s\n", ptr->p_cmd, ptr->p_func_desc);
    }
}

void cli_db_sc_truncate(FILE *fp, uint32_t argc, const char **argv)
{
    //
}

// ROOT DB BLOCK
void cli_db_block(FILE *fp, uint32_t argc, const char **argv)
{
    if (argc)
    {
        for (const cli_func_t *ptr = cli_db_block_func; ptr->p_cmd != NULL; ++ptr)
        {
            if(STRCMP_M( argv[0], ptr->p_cmd) == 0)
            {
                ptr->cli_handler(fp, argc-1, (const char **)&argv[1]);
                break;
            }
        }
    }
    else
    {
        DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO,(void*)"%s\n", __FUNCTION__);
    }
}

void cli_db_block_help(FILE *fp, uint32_t argc, const char **argv)
{
    for (const cli_func_t *ptr = cli_db_block_func; ptr->p_cmd != NULL; ++ptr)
    {
        cli_utils_print(" - %s\t-\t%s\n", ptr->p_cmd, ptr->p_func_desc);
    }
}

void cli_db_block_truncate(FILE *fp, uint32_t argc, const char **argv)
{
    //
}

// ROOT TEST
void cli_test(FILE *fp, uint32_t argc, const char **argv)
{
    if (argc)
    {
        for (const cli_func_t *ptr = cli_test_func; ptr->p_cmd != NULL; ++ptr)
        {
            if(STRCMP_M( argv[0], ptr->p_cmd) == 0)
            {
                ptr->cli_handler(fp, argc-1, (const char **)&argv[1]);
                break;
            }
        }
    }
    else
    {
        DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO,(void*)"%s\n", __FUNCTION__);
    }
}

void cli_test_help(FILE *fp, uint32_t argc, const char **argv)
{
    for (const cli_func_t *ptr = cli_test_func; ptr->p_cmd != NULL; ++ptr)
    {
        cli_utils_print(" - %s\t-\t%s\n", ptr->p_cmd, ptr->p_func_desc);
    }
}

// ROOT TEST CRYPTO
void cli_test_crypto(FILE *fp, uint32_t argc, const char **argv)
{
    if (argc)
    {
        for (const cli_func_t *ptr = cli_test_crypto_func; ptr->p_cmd != NULL; ++ptr)
        {
            if(STRCMP_M( argv[0], ptr->p_cmd) == 0)
            {
                ptr->cli_handler(fp, argc-1, (const char **)&argv[1]);
                break;
            }
        }
    }
    else
    {
        DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO,(void*)"%s\n", __FUNCTION__);
    }
}

void cli_test_crypto_help(FILE *fp, uint32_t argc, const char **argv)
{
    for (const cli_func_t *ptr = cli_test_crypto_func; ptr->p_cmd != NULL; ++ptr)
    {
        cli_utils_print(" - %s\t-\t%s\n", ptr->p_cmd, ptr->p_func_desc);
    }
}

void cli_test_crypto_kdf2(FILE *fp, uint32_t argc, const char **argv)
{
    int32_t ret;
    const EVP_MD *md = EVP_sha256();
#if 0
    uint8_t ss[24] ={   0x96, 0xC0, 0x56, 0x19, 0xD5, 0x6C, 0x32, 0x8A, 0xB9, 0x5F, 
                        0xE8, 0x4B, 0x18, 0x26, 0x4B, 0x08, 0x72, 0x5B, 0x85, 0xE3, 
                        0x3F, 0xD3, 0x4F, 0x08 };
    uint8_t dkey[16];
    uint32_t key_len = 16;
    uint8_t kdp[16];
    uint32_t kdp_len = 0;
    // key = 0x 443024c3 dae66b95 e6f56706 01558f71
#else
    uint8_t ss[24] ={   0x22, 0x51, 0x8B, 0x10, 0xE7, 0x0F, 0x2A, 0x3F, 0x24, 0x38, 
                        0x10, 0xAE, 0x32, 0x54, 0x13, 0x9E, 0xFB, 0xEE, 0x04, 0xAA, 
                        0x57, 0xC7, 0xAF, 0x7D };
    uint8_t dkey[128];
    int32_t key_len = 128;
    uint8_t kdp[16] = { 0x75, 0xEE, 0xF8, 0x1A, 0xA3, 0x04, 0x1E, 0x33, 0xB8, 0x09, 
                        0x71, 0x20, 0x3D, 0x2C, 0x0C, 0x52 };
    int32_t kdp_len = 16;
    // Key = 0x 
    // c498af77 161cc59f 2962b9a7 13e2b215
    // 152d1397 66ce34a7 76df1186 6a69bf2e
    // 52a13d9c 7c6fc878 c50c5ea0 bc7b00e0
    // da2447cf d874f6cf 92f30d00 97111485
    // 500c90c3 af8b4878 72d04685 d14c8d1d
    // c8d7fa08 beb0ce0a babc11f0 bd496269
    // 142d4352 5a78e5bc 79a17f59 676a5706
    // dc54d54d 4d1f0bd7 e386128e c26afc21

#endif
    ret = openssl_kdf2(md, ss, 24, kdp, kdp_len, key_len, dkey);

    DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO, (void *)"openssl_kdf2 ret(%d)\n", ret);

    DBG_FD_DUMP(fp, DBG_CLI, DBG_INFO, (void *)"dkey", dkey, key_len);
}

void cli_test_crypto_base58(FILE *fp, uint32_t argc, const char **argv)
{
    char *p_enc, *p_dec;

    // Base58 Encode
    p_enc = base58_encode((char *)"fabb88b1152463b562317a1ac415043abc136c7d565cb61d21157311a33aeff8");
    DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO, (void *)"result=%s\n", p_enc);

    // Base58 Decode
    p_dec=base58_decode(p_enc);
    DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO, (void *)"result=%s\n", p_dec);
    OPENSSL_free(p_dec);

    FREE_M(p_enc);
}

// ROOT TEST EC
void cli_test_ec(FILE *fp, uint32_t argc, const char **argv)
{
    if (argc)
    {
        for (const cli_func_t *ptr = cli_test_ec_func; ptr->p_cmd != NULL; ++ptr)
        {
            if(STRCMP_M( argv[0], ptr->p_cmd) == 0)
            {
                ptr->cli_handler(fp, argc-1, (const char **)&argv[1]);
                break;
            }
        }
    }
    else
    {
        DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO,(void*)"%s\n", __FUNCTION__);
    }
}

void cli_test_ec_help(FILE *fp, uint32_t argc, const char **argv)
{
    for (const cli_func_t *ptr = cli_test_ec_func; ptr->p_cmd != NULL; ++ptr)
    {
        cli_utils_print(" - %s\t-\t%s\n", ptr->p_cmd, ptr->p_func_desc);
    }
}

void cli_test_ec_gen(FILE *fp, uint32_t argc, const char **argv)
{
    openssl_ec_key_gen(NULL);
}

void cli_test_ec_ecdsa(FILE *fp, uint32_t argc, const char **argv)
{
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
    uint8_t data[32];
    SSL_SIG_U sig_hex;
    int32_t ret;

    for (int i = 0; i < 32; i++) {
        data[i] = i;
    }
    
    ret = openssl_ecdsa_sig(p_cons_cntx->b_enc_prikey, (char *)p_cons_cntx->my_prikey_path, data, sizeof(data), &sig_hex);
    DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO, (void *)"sig ret(%d)\r\n", ret);

    ret = openssl_ecdsa_verify_pubkey_path((char *)p_cons_cntx->my_pubkey_path, data, sizeof(data), &sig_hex);
    DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO, (void *)"verify ret(%d)\r\n", ret);
}

void cli_test_ec_ecies(FILE *fp, uint32_t argc, const char **argv)
{
#if (ECIES_TEST == ENABLED)
    openssl_ecies_test();
#endif // ECIES_TEST
}

void cli_test_ec_verify(FILE *fp, uint32_t argc, const char **argv)
{
    uint8_t data_str_hex[32];
    util_str2hex_temp("559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd", data_str_hex, 32, false);
    SSL_SIG_U sig_hex;
    util_str2hex_temp("A7C97CEF667F2D687BFF9457407244E199FCBB9E7C8895BF7C1FC53C79F1AD78", sig_hex.ec.r, SIG_R_SIZE, false);
    util_str2hex_temp("864AF578EFE3A5866457B57E98ADDDBEF3791C0EF74122F7AB7A849FF03CC960", sig_hex.ec.s, SIG_S_SIZE, false);
    uint8_t comp_pubkey_hex[COMP_PUBKEY_SIZE];
    util_str2hex_temp("037A7ED2B23B16B3DFA5351DE64FDB96E339807278A032D700E3D88734BF6E67EC", comp_pubkey_hex, COMP_PUBKEY_SIZE, false);
    
    openssl_ecdsa_verify(data_str_hex, HASH_SIZE, &sig_hex, comp_pubkey_hex);
}

void cli_test_ec_pkcomp(FILE *fp, uint32_t argc, const char **argv)
{
    char uncomp_pubkey_str[UNCOMP_PUBKEY_STR_SIZE];
    char comp_pubkey[COMP_PUBKEY_STR_SIZE];
    
    STRCPY_M(uncomp_pubkey_str,"041702BC48DDB98AAFE39907EEF0FA6F6D591C2042C0856A4ADF9AA5DB527E84DE1A7D25CF667B453CAE91ADA5BA4974F6E5282A099E8CFA823C02BEC261C6D6E0");
    DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO, (void *)"Uncompressed Pubkey : %s\r\n", uncomp_pubkey_str);
    
    openssl_ec_pubkey_compress(uncomp_pubkey_str, comp_pubkey);
    DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO, (void *)"Compressed Pubkey : %s\r\n", comp_pubkey);
}

void cli_test_ec_pkdecomp(FILE *fp, uint32_t argc, const char **argv)
{
    char comp_pubkey_str[COMP_PUBKEY_STR_SIZE];
    STRCPY_M(comp_pubkey_str,"021702BC48DDB98AAFE39907EEF0FA6F6D591C2042C0856A4ADF9AA5DB527E84DE");
    DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO, (void *)"Compressed Pubkey : %s\r\n", comp_pubkey_str);
    
    char uncomp_pubkey[UNCOMP_PUBKEY_STR_SIZE];
    
    openssl_ec_pubkey_decompress(comp_pubkey_str,uncomp_pubkey);
    DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO, (void *)"Uncompressed Pubkey : %s\r\n", uncomp_pubkey);
}

void cli_test_ec_pem2hex(FILE *fp, uint32_t argc, const char **argv)
{
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
    uint8_t comp_pubkey[COMP_PUBKEY_SIZE];
    
    //
    openssl_ec_pubkey_pem2hex(p_cons_cntx->my_pubkey_path, comp_pubkey);
    
    DBG_FD_DUMP(fp, DBG_CLI, DBG_INFO, (void *)"comp_pubkey\n",comp_pubkey,COMP_PUBKEY_SIZE);
}

void cli_test_ec_hex2pem(FILE *fp, uint32_t argc, const char **argv)
{
    uint8_t pubkey[COMP_PUBKEY_SIZE] = {0x02, 
            0x35, 0x4D, 0x54, 0xBD, 0xC0, 0xB9, 0xD9, 0x4A, 0x84, 0x1C, 0xFD, 0xD0, 0xBD, 0x25, 0xB9, 0xC6, 
            0x1B, 0x60, 0x3F, 0xBE, 0x47, 0xD9, 0x5E, 0xCB, 0xF8, 0xB4, 0x45, 0x61, 0x4A, 0xAC, 0x55, 0x9D};
    
    openssl_ec_pubkey_hex2pem((char *)"key/pubkey_test.pem", pubkey);
}

// ROOT TEST ED
void cli_test_ed(FILE *fp, uint32_t argc, const char **argv)
{
    if (argc)
    {
        for (const cli_func_t *ptr = cli_test_ed_func; ptr->p_cmd != NULL; ++ptr)
        {
            if(STRCMP_M( argv[0], ptr->p_cmd) == 0)
            {
                ptr->cli_handler(fp, argc-1, (const char **)&argv[1]);
                break;
            }
        }
    }
    else
    {
        DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO,(void*)"%s\n", __FUNCTION__);
    }
}

void cli_test_ed_help(FILE *fp, uint32_t argc, const char **argv)
{
    for (const cli_func_t *ptr = cli_test_ed_func; ptr->p_cmd != NULL; ++ptr)
    {
        cli_utils_print(" - %s\t-\t%s\n", ptr->p_cmd, ptr->p_func_desc);
    }
}

void cli_test_ed_edgen(FILE *fp, uint32_t argc, const char **argv)
{
    openssl_ed25519_keygen((char *)"key/ed_");
}

void cli_test_ed_ed25519(FILE *fp, uint32_t argc, const char **argv)
{
    SSL_SIG_U sig_hex;
    uint32_t message_len = 32;
    uint8_t message[32] = {0x96, 0xC0, 0x56, 0x19, 0xD5, 0x6C, 0x32, 0x8A, 
                           0xB9, 0x5F, 0xE8, 0x4B, 0x18, 0x26, 0x4B, 0x08, 
                           0x72, 0x5B, 0x85, 0xE3, 0x3F, 0xD3, 0x4F, 0x08,
                           0x72, 0x5B, 0x85, 0xE3, 0x3F, 0xD3, 0x4F, 0x08};
#if (OPENSSL_111 == ENABLED)
    openssl_ed25519_sig(false, (char *)"key/ed_privkey.pem", message, message_len, &sig_hex);
    openssl_ed25519_verify_pubkey_path((char *)"key/ed_pubkey.pem", message, message_len, &sig_hex);
#elif (OPENSSL_102 == ENABLED)
    openssl_ed25519_sig(false, (char *)"key/ed_privkey.hex", message, message_len, &sig_hex);
#endif // OPENSSL_111
}

void cli_test_ed_edtest(FILE *fp, uint32_t argc, const char **argv)
{
#if (ED25519_TEST == ENABLED)
    openssl_ed25519_test();
#endif // ED25519_TEST
}

void cli_test_ed_xgen(FILE *fp, uint32_t argc, const char **argv)
{
    openssl_x25519_keygen((char *)"key/x_");
}

void cli_test_ed_xkeytest(FILE *fp, uint32_t argc, const char **argv)
{
#if (X25519_TEST == ENABLED)
    openssl_x25519_key_test();
#endif // X25519_TEST
}

void cli_test_ed_x25519(FILE *fp, uint32_t argc, const char **argv)
{
#if (X25519_TEST == ENABLED)
    openssl_x25519_test();
#endif // X25519_TEST
}

// ROOT TEST RSA
void cli_test_rsa(FILE *fp, uint32_t argc, const char **argv)
{
    if (argc)
    {
        for (const cli_func_t *ptr = cli_test_rsa_func; ptr->p_cmd != NULL; ++ptr)
        {
            if(STRCMP_M( argv[0], ptr->p_cmd) == 0)
            {
                ptr->cli_handler(fp, argc-1, (const char **)&argv[1]);
                break;
            }
        }
    }
    else
    {
        DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO,(void*)"%s\n", __FUNCTION__);
    }
}

void cli_test_rsa_help(FILE *fp, uint32_t argc, const char **argv)
{
    for (const cli_func_t *ptr = cli_test_rsa_func; ptr->p_cmd != NULL; ++ptr)
    {
        cli_utils_print(" - %s\t-\t%s\n", ptr->p_cmd, ptr->p_func_desc);
    }
}

void cli_test_rsa_gen(FILE *fp, uint32_t argc, const char **argv)
{
    openssl_rsa_keypair_gen();
}

void cli_test_rsa_encdec(FILE *fp, uint32_t argc, const char **argv)
{
    char rsa_pubkey_path[]= "rsa_pubkey.pem";
    char rsa_privkey_path[] = "rsa_privkey.pem";
    unsigned char cipher[2048], plain[2048];
    int size_plain, size_cipher;
    
    // maximum size
    unsigned char rsa_msg[] = "I like coding.I like coding.I like coding.I like coding.I like coding.I like coding.I like coding.I like coding.";
    DBG_FD_DUMP(fp, DBG_CLI, DBG_NONE, (void *)"rsa_msg", rsa_msg, sizeof(rsa_msg));
    
    openssl_rsa_msg_encrypt(rsa_pubkey_path, rsa_msg, sizeof(rsa_msg), cipher, &size_cipher);
    DBG_FD_DUMP(fp, DBG_CLI, DBG_NONE, (void *)"rsa_enc", cipher, size_cipher);
    
    openssl_rsa_msg_decrypt(rsa_privkey_path, cipher, size_cipher, plain, &size_plain);
    DBG_FD_DUMP(fp, DBG_CLI, DBG_NONE, (void *)"rsa_dec", plain, size_plain);
}

// ROOT TEST HASH
void cli_test_hash(FILE *fp, uint32_t argc, const char **argv)
{
    if (argc)
    {
        for (const cli_func_t *ptr = cli_test_hash_func; ptr->p_cmd != NULL; ++ptr)
        {
            if(STRCMP_M( argv[0], ptr->p_cmd) == 0)
            {
                ptr->cli_handler(fp, argc-1, (const char **)&argv[1]);
                break;
            }
        }
    }
    else
    {
        DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO,(void*)"%s\n", __FUNCTION__);
    }
}

void cli_test_hash_help(FILE *fp, uint32_t argc, const char **argv)
{
    for (const cli_func_t *ptr = cli_test_hash_func; ptr->p_cmd != NULL; ++ptr)
    {
        cli_utils_print(" - %s\t-\t%s\n", ptr->p_cmd, ptr->p_func_desc);
    }
}

void cli_test_hash_sha256(FILE *fp, uint32_t argc, const char **argv)
{
    uint8_t hash[HASH_SIZE];
    uint8_t data[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    openssl_sha256(hash, data, sizeof(data));
    DBG_FD_DUMP(fp, DBG_CLI, DBG_INFO, (void *)"Hash Gen", hash, 32);
}

// ROOT TEST AES
void cli_test_aes(FILE *fp, uint32_t argc, const char **argv)
{
    if (argc)
    {
        for (const cli_func_t *ptr = cli_test_aes_func; ptr->p_cmd != NULL; ++ptr)
        {
            if(STRCMP_M( argv[0], ptr->p_cmd) == 0)
            {
                ptr->cli_handler(fp, argc-1, (const char **)&argv[1]);
                break;
            }
        }
    }
    else
    {
        DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO,(void*)"%s\n", __FUNCTION__);
    }
}

void cli_test_aes_help(FILE *fp, uint32_t argc, const char **argv)
{
    for (const cli_func_t *ptr = cli_test_aes_func; ptr->p_cmd != NULL; ++ptr)
    {
        cli_utils_print(" - %s\t-\t%s\n", ptr->p_cmd, ptr->p_func_desc);
    }
}

void cli_test_aes_cbc(FILE *fp, uint32_t argc, const char **argv)
{
    uint8_t enc_text[1024];
    uint8_t text[16] = { 0x75, 0xEE, 0xF8, 0x1A, 0xA3, 0x04, 0x1E, 0x33, 0xB8, 0x09, 0x71, 0x20, 0x3D, 0x2C, 0x0C, 0x52 };
    uint32_t enc_len, text_len = 16;

    uint8_t key[OPENSSL_SYM_KEY_LEN] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };
    unsigned char iv[AES_BLOCK_SIZE];
    MEMSET_M(iv, 0x00, AES_BLOCK_SIZE);

    DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO, (void *)"aes!!!\r\n");

    enc_len = openssl_aes_cbc_encrypt(text, 16, key, iv, enc_text);
    DBG_FD_DUMP(fp, DBG_CLI, DBG_INFO, (void *) "aes_enc", (uint8_t *)enc_text, enc_len);

    text_len = openssl_aes_cbc_decrypt(enc_text, enc_len, key, iv, text);
    DBG_FD_DUMP(fp, DBG_CLI, DBG_INFO, (void *) "aes_dec", (uint8_t *)text, text_len);
}

void cli_test_aes_pwenc(FILE *fp, uint32_t argc, const char **argv)
{
    if (!argc)
    {
        DBG_FD_PRINT(fp, DBG_CLI, DBG_ERROR, (void *)"Error : argc(%d)\r\n", argc);
        return;
    }
    
    openssl_aes_encrypt_pw((char *)"key/me/seed", (uint8_t *)argv[0], STRLEN_M(argv[0]), (char *)"key/me/enc_pw");
}

void cli_test_aes_pwdec(FILE *fp, uint32_t argc, const char **argv)
{
    uint8_t *p_pw;
    uint32_t pw_len;
    
    p_pw = openssl_aes_decrypt_pw((char *)"./../../conf/test/seed", (char *)"./../../conf/test/redis_enc_pw", &pw_len);
    
    DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO, (void *)"my_pw : %s - len(%d)\r\n", (uint8_t *)p_pw, pw_len);
    
    FREE_M(p_pw);
}

void cli_test_aes_ecprvenc(FILE *fp, uint32_t argc, const char **argv)
{
    uint8_t *p_pw;
    uint32_t pw_len;
    
    p_pw = openssl_aes_decrypt_pw(NULL, NULL, &pw_len);

    openssl_aes_encrpt_file((char *)"key/me/privkey.pem", (char *)"key/me/privkey.fin", (uint8_t *)p_pw, pw_len);

    FREE_M(p_pw);
}

void cli_test_aes_ecprvdec(FILE *fp, uint32_t argc, const char **argv)
{
    uint8_t *p_dec;

    uint8_t *p_pw;
    uint32_t pw_len;
    
    p_pw = openssl_aes_decrypt_pw(NULL, NULL, &pw_len);

    p_dec = openssl_aes_decrypt_file((char *)"key/me/privkey.fin", (uint8_t *)p_pw, pw_len);
    
    FREE_M(p_dec);
    FREE_M(p_pw);
}

void cli_test_aes_edprvenc(FILE *fp, uint32_t argc, const char **argv)
{
    uint8_t *p_pw;
    uint32_t pw_len;
    
    p_pw = openssl_aes_decrypt_pw(NULL, NULL, &pw_len);

    openssl_aes_encrpt_file((char *)"key/me/ed_privkey.pem", (char *)"key/me/ed_privkey.fin", (uint8_t *)p_pw, pw_len);

    FREE_M(p_pw);
}

void cli_test_aes_edprvdec(FILE *fp, uint32_t argc, const char **argv)
{
    uint8_t *p_dec;

    uint8_t *p_pw;
    uint32_t pw_len;
    
    p_pw = openssl_aes_decrypt_pw(NULL, NULL, &pw_len);

    p_dec = openssl_aes_decrypt_file((char *)"key/me/ed_privkey.fin", (uint8_t *)p_pw, pw_len);
    
    FREE_M(p_dec);
    FREE_M(p_pw);
}


// ROOT TEST HSM
void cli_test_hsm(FILE *fp, uint32_t argc, const char **argv)
{
    if (argc)
    {
        for (const cli_func_t *ptr = cli_test_hsm_func; ptr->p_cmd != NULL; ++ptr)
        {
            if(STRCMP_M( argv[0], ptr->p_cmd) == 0)
            {
                ptr->cli_handler(fp, argc-1, (const char **)&argv[1]);
                break;
            }
        }
    }
    else
    {
        DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO,(void*)"%s\n", __FUNCTION__);
    }
}

void cli_test_hsm_help(FILE *fp, uint32_t argc, const char **argv)
{
    for (const cli_func_t *ptr = cli_test_hsm_func; ptr->p_cmd != NULL; ++ptr)
    {
        cli_utils_print(" - %s\t-\t%s\n", ptr->p_cmd, ptr->p_func_desc);
    }
}

void cli_test_hsm_yubihsm(FILE *fp, uint32_t argc, const char **argv)
{
    //
}

// ROOT TEST DB
void cli_test_db(FILE *fp, uint32_t argc, const char **argv)
{
    if (argc)
    {
        for (const cli_func_t *ptr = cli_test_db_func; ptr->p_cmd != NULL; ++ptr)
        {
            if(STRCMP_M( argv[0], ptr->p_cmd) == 0)
            {
                ptr->cli_handler(fp, argc-1, (const char **)&argv[1]);
                break;
            }
        }
    }
    else
    {
        DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO,(void*)"%s\n", __FUNCTION__);
    }
}

void cli_test_db_help(FILE *fp, uint32_t argc, const char **argv)
{
    for (const cli_func_t *ptr = cli_test_db_func; ptr->p_cmd != NULL; ++ptr)
    {
        cli_utils_print(" - %s\t-\t%s\n", ptr->p_cmd, ptr->p_func_desc);
    }
}

#if defined(USE_MYSQL)
// ROOT TEST DB MYSQL
void cli_test_db_mysql(FILE *fp, uint32_t argc, const char **argv)
{
    if (argc)
    {
        for (const cli_func_t *ptr = cli_test_db_mysql_func; ptr->p_cmd != NULL; ++ptr)
        {
            if(STRCMP_M( argv[0], ptr->p_cmd) == 0)
            {
                ptr->cli_handler(fp, argc-1, (const char **)&argv[1]);
                break;
            }
        }
    }
    else
    {
        DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO,(void*)"%s\n", __FUNCTION__);
    }
}

void cli_test_db_mysql_help(FILE *fp, uint32_t argc, const char **argv)
{
    for (const cli_func_t *ptr = cli_test_db_mysql_func; ptr->p_cmd != NULL; ++ptr)
    {
        cli_utils_print(" - %s\t-\t%s\n", ptr->p_cmd, ptr->p_func_desc);
    }
}
#endif // USE_MYSQL

#if defined(USE_MONGODB)
// ROOT TEST DB MONGO
void cli_test_db_mongo(FILE *fp, uint32_t argc, const char **argv)
{
    if (argc)
    {
        for (const cli_func_t *ptr = cli_test_db_mongo_func; ptr->p_cmd != NULL; ++ptr)
        {
            if(STRCMP_M( argv[0], ptr->p_cmd) == 0)
            {
                ptr->cli_handler(fp, argc-1, (const char **)&argv[1]);
                break;
            }
        }
    }
    else
    {
        DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO,(void*)"%s\n", __FUNCTION__);
    }
}

void cli_test_db_mongo_help(FILE *fp, uint32_t argc, const char **argv)
{
    for (const cli_func_t *ptr = cli_test_db_mongo_func; ptr->p_cmd != NULL; ++ptr)
    {
        cli_utils_print(" - %s\t-\t%s\n", ptr->p_cmd, ptr->p_func_desc);
    }
}

void cli_test_db_mongo_init(FILE *fp, uint32_t argc, const char **argv)
{
    //
}

void cli_test_db_mongo_truncate(FILE *fp, uint32_t argc, const char **argv)
{
    DB_TRUNCATE();
}

void cli_test_db_mongo_tx(FILE *fp, uint32_t argc, const char **argv)
{
    static volatile char sc_hash[] = "ooooooooo0qqqqqqqqq0rrrrrrrrr012";

    uint64_t db_key = 0x2000000000000000;
    static volatile uint64_t db_idx = 0;

    uint64_t blk_num = 2;

    uint32_t tx_cnt;
    
    DB_INSERT_T_BLK_TX(blk_num, db_key+db_idx, (uint8_t *)sc_hash);

    db_idx++;

    tx_cnt = 0;
    tx_cnt = DB_SELECT_COUNT_F_BLK_TXS_W_BN(blk_num);

    DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO,(void*)"tx_cnt = %d\n", tx_cnt);
}

void cli_test_db_mongo_tx_bulk(FILE *fp, uint32_t argc, const char **argv)
{
    DB_RESULT_E db_ret;
    
    char sc_hash[] = "nnnnnnnnn0qqqqqqqqq0rrrrrrrrr012";
    uint64_t db_key = 0x1000000000000000;
    uint64_t blk_num = 1;
    void  *arg   = NULL;
    bool  b_last = false;

    uint32_t cnt, tx_cnt;

    tx_cnt = 5;
    
    arg  = DB_INSERT_T_BLK_TX_START(0);
    for (cnt=0; cnt<tx_cnt; cnt++)
    {
        if ((cnt+1) == tx_cnt)
        {
            b_last = true;
        }
        
        sc_hash[cnt]  -= 'a' - 'A';
        db_ret  = DB_INSERT_T_BLK_TX_PROCESS(arg, b_last, blk_num, db_key+cnt, (uint8_t *)sc_hash);
        if (DB_RESULT_SUCCESS != db_ret)
        {
            ASSERT_M(0);
        }
    }
    DB_INSERT_T_BLK_TX_END(arg);

    tx_cnt = 0;
    tx_cnt = DB_SELECT_COUNT_F_BLK_TXS_W_BN(blk_num);

    DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO,(void*)"tx_cnt = %d\n", tx_cnt);
}

void cli_test_db_mongo_tx_update(FILE *fp, uint32_t argc, const char **argv)
{
    
}

void cli_test_db_mongo_block(FILE *fp, uint32_t argc, const char **argv)
{
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
    P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();

    CONS_LIGHT_BLK_T light_blk;
    char blk_hash[] = "xxxxxxxxx0yyyyyyyyy0zzzzzzzzz012";
    char sig[SIG_SIZE];
    char sig_pubkey[COMP_PUBKEY_SIZE];
    uint32_t tx_cnt;
    uint32_t idx;
    
    uint64_t blk_idx, blk_cnt;

    blk_cnt = 5;

    // Insert
    for (blk_idx=0; blk_idx<blk_cnt; blk_idx++)
    {
        MEMSET_M(sig, 'g' + blk_idx, SIG_SIZE);
        tx_cnt = 5;
        
        for (idx=0; idx<SIG_SIZE; idx++)
        {
            switch(idx%7)
            {
                case 0: case 4:
                {
                    sig[idx]  = 'A' + idx%26 + blk_idx;
                } break;
                case 3: case 6:
                {
                    sig[idx]  = '0' + idx%10 + blk_idx;
                } break;
                default:
                {
                    sig[idx]  = 'a' + idx%26 + blk_idx;
                } break;
            }
        }
        
        light_blk.blk_num  = blk_idx;
        light_blk.p2p_addr = p_p2p_cntx->my_p2p_addr.u64;
        light_blk.bgt = time(NULL);
        MEMCPY_M(light_blk.pbh, blk_hash, HASH_SIZE);
        light_blk.tx_cnt = tx_cnt;
        MEMCPY_M(light_blk.blk_hash, blk_hash, HASH_SIZE);
        MEMCPY_M(light_blk.sig, sig, SIG_SIZE);
        MEMCPY_M(light_blk.sig_pubkey, sig_pubkey, COMP_PUBKEY_SIZE);
        
        DB_INSERT_T_BLK_CONTENTS(&light_blk);
    }

    //
    for (blk_idx=0; blk_idx<blk_cnt; blk_idx++)
    {
        MEMSET_M(&light_blk, 0x00, sizeof(CONS_LIGHT_BLK_T));
        
        DB_SELECT_BLK_F_BLK_CONTENTS_W_BN(blk_idx, &light_blk);

        DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO,(void*)"blk_num  = 0x%016llX\n", light_blk.blk_num);
        DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO,(void*)"p2p_addr  = 0x%016llX\n", light_blk.p2p_addr);
        DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO,(void*)"blk_gen_time  = 0x%016llX\n", light_blk.bgt);
        DBG_FD_DUMP(fp, DBG_CLI, DBG_INFO, (void *)"prv_blk_hash", light_blk.pbh, HASH_SIZE);
        DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO,(void*)"tx_cnt  = %d\n", light_blk.tx_cnt);
        DBG_FD_DUMP(fp, DBG_CLI, DBG_INFO, (void *)"blk_hash", light_blk.blk_hash, HASH_SIZE);
        DBG_FD_DUMP(fp, DBG_CLI, DBG_INFO, (void *)"sig", light_blk.sig, SIG_SIZE);
        DBG_FD_DUMP(fp, DBG_CLI, DBG_INFO, (void *)"sig_pubkey", light_blk.sig_pubkey, COMP_PUBKEY_SIZE);
    }
}

#endif // USE_MONGODB

// ROOT TEST DB REDIS
void cli_test_db_redis(FILE *fp, uint32_t argc, const char **argv)
{
    if (argc)
    {
        for (const cli_func_t *ptr = cli_test_db_redis_func; ptr->p_cmd != NULL; ++ptr)
        {
            if(STRCMP_M( argv[0], ptr->p_cmd) == 0)
            {
                ptr->cli_handler(fp, argc-1, (const char **)&argv[1]);
                break;
            }
        }
    }
    else
    {
        DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO,(void*)"%s\n", __FUNCTION__);
    }
}

void cli_test_db_redis_help(FILE *fp, uint32_t argc, const char **argv)
{
    for (const cli_func_t *ptr = cli_test_db_redis_func; ptr->p_cmd != NULL; ++ptr)
    {
        cli_utils_print(" - %s\t-\t%s\n", ptr->p_cmd, ptr->p_func_desc);
    }
}

void cli_test_db_redis_test(FILE *fp, uint32_t argc, const char **argv)
{
    //
}

// ROOT TEST MSG
void cli_test_msg(FILE *fp, uint32_t argc, const char **argv)
{
    if (argc)
    {
        for (const cli_func_t *ptr = cli_test_msg_func; ptr->p_cmd != NULL; ++ptr)
        {
            if(STRCMP_M( argv[0], ptr->p_cmd) == 0)
            {
                ptr->cli_handler(fp, argc-1, (const char **)&argv[1]);
                break;
            }
        }
    }
    else
    {
        DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO,(void*)"%s\n", __FUNCTION__);
    }
}

void cli_test_msg_help(FILE *fp, uint32_t argc, const char **argv)
{
    for (const cli_func_t *ptr = cli_test_msg_func; ptr->p_cmd != NULL; ++ptr)
    {
        cli_utils_print(" - %s\t-\t%s\n", ptr->p_cmd, ptr->p_func_desc);
    }
}

// ROOT TEST TIMER
void cli_test_timer(FILE *fp, uint32_t argc, const char **argv)
{
    if (argc)
    {
        for (const cli_func_t *ptr = cli_test_timer_func; ptr->p_cmd != NULL; ++ptr)
        {
            if(STRCMP_M( argv[0], ptr->p_cmd) == 0)
            {
                ptr->cli_handler(fp, argc-1, (const char **)&argv[1]);
                break;
            }
        }
    }
    else
    {
        DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO,(void*)"%s\n", __FUNCTION__);
    }
}

void cli_test_timer_help(FILE *fp, uint32_t argc, const char **argv)
{
    for (const cli_func_t *ptr = cli_test_timer_func; ptr->p_cmd != NULL; ++ptr)
    {
        cli_utils_print(" - %s\t-\t%s\n", ptr->p_cmd, ptr->p_func_desc);
    }
}

void cli_test_timer_trace(FILE *fp, uint32_t argc, const char **argv)
{
    timer_trace();
}


// ROOT TEST UTIL
void cli_test_util(FILE *fp, uint32_t argc, const char **argv)
{
    if (argc)
    {
        for (const cli_func_t *ptr = cli_test_util_func; ptr->p_cmd != NULL; ++ptr)
        {
            if(STRCMP_M( argv[0], ptr->p_cmd) == 0)
            {
                ptr->cli_handler(fp, argc-1, (const char **)&argv[1]);
                break;
            }
        }
    }
    else
    {
        DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO,(void*)"%s\n", __FUNCTION__);
    }
}

void cli_test_util_help(FILE *fp, uint32_t argc, const char **argv)
{
    for (const cli_func_t *ptr = cli_test_util_func; ptr->p_cmd != NULL; ++ptr)
    {
        cli_utils_print(" - %s\t-\t%s\n", ptr->p_cmd, ptr->p_func_desc);
    }
}

void cli_test_util_crc32_cunit(void)
{
    uint32_t pkt_len = 9;
    unsigned char pkt_data[13]={0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0xCB,0xF4,0x39,0x26};

    CU_ASSERT_EQUAL(util_cal_crc32(pkt_data, pkt_len), 0xCBF43926);
}

void cli_test_util_crc32(FILE *fp, uint32_t argc, const char **argv)
{
#if 1
    CU_pSuite suite = NULL;
    CU_initialize_registry();

    suite = CU_add_suite("[util_cal_crc32() func test]", NULL, NULL);
    
    CU_add_test(suite, "cli_test_util_crc32_cunit", cli_test_util_crc32_cunit);

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    //CU_console_run_tests();

    CU_cleanup_registry();
#else
    uint32_t crc_v, pkt_len;
    int32_t ret;
    
    pkt_len = 9;
    unsigned char pkt_data[13]={0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0xCB,0xF4,0x39,0x26};
    
    DBG_FD_DUMP(fp, DBG_CLI, DBG_INFO, (void *)"pkt_data ori", pkt_data, pkt_len+UTIL_CRC_LEN);
    
    crc_v = util_cal_crc32(pkt_data, pkt_len);
    
    DBG_FD_DUMP(fp, DBG_CLI, DBG_INFO, (void *)"pkt_data cal", pkt_data, pkt_len+UTIL_CRC_LEN);
    DBG_FD_PRINT (fp, DBG_CLI, DBG_INFO, (void *)"cal crc 0x%08X\r\n", crc_v);
    
    ret = util_chk_crc32(pkt_data, pkt_len);
    DBG_FD_PRINT (fp, DBG_CLI, DBG_INFO, (void *)"chk crc %d\r\n", ret);
#endif
}

void cli_test_util_crc32a(FILE *fp, uint32_t argc, const char **argv)
{
#if (UTIL_CRC_ALGO_1 == ENABLED)
    uint32_t crc_v, pkt_len;
    
    pkt_len = 9;
    unsigned char pkt_data[13]={0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0xCB,0xF4,0x39,0x26};
    
    crc_v = util_crc32a(pkt_data, pkt_len);
    
    DBG_FD_PRINT (fp, DBG_CLI, DBG_INFO, (void *)"crc1 0x%08X\r\n", crc_v);
#endif // UTIL_CRC_ALGO_1
}

void cli_test_util_crc32b(FILE *fp, uint32_t argc, const char **argv)
{
#if (UTIL_CRC_ALGO_2 == ENABLED)
    uint32_t crc_v, pkt_len;
    
    pkt_len = 9;
    unsigned char pkt_data[13]={0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0xCB,0xF4,0x39,0x26};
    
    UTIL_CNTX_T *p_util_cntx = util_get_cntx();
    
    crc_v = util_crc32b(pkt_data, pkt_len, p_util_cntx->crc_table);
    
    DBG_FD_PRINT (fp, DBG_CLI, DBG_INFO, (void *)"crc2 0x%08X\r\n", crc_v);
#endif // UTIL_CRC_ALGO_2
}

void cli_test_util_slice(FILE *fp, uint32_t argc, const char **argv)
{
    CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
    uint32_t start, end;
    char *p_buf;
    
    end = STRLEN_M(p_cons_cntx->prikey_name);
    start = end - 3;
    
    p_buf = util_slice_str(p_cons_cntx->prikey_name, start, end);
    if (p_buf)
    {
        util_str_upper_case(p_buf, STRLEN_M(p_buf));
        util_str_lower_case(p_buf, STRLEN_M(p_buf));
    
        DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO, (void *)"buf : %s - len(%d)\r\n", p_buf, STRLEN_M(p_buf));

        FREE_M(p_buf);
    }
}

void cli_test_util_sysinfo(FILE *fp, uint32_t argc, const char **argv)
{
    uint8_t *p_bios_sn = NULL;
    uint32_t len;
    
    util_get_my_ip_addr();
    //util_cpu_serial_info();
    //util_hdd_serial_info();
    //util_bios_serial_info();
    
    len = util_bios_uuid_info((uint8_t **)&p_bios_sn);
    DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO, (void *)"system uuid2 len(%d) (%s)\n", len, p_bios_sn);
    FREE_M(p_bios_sn);
}

void cli_test_util_jsonc(FILE *fp, uint32_t argc, const char **argv)
{
//{ "header": { "dataSize": 1000, "dataType": "text", "macAddress": "00:00:00:00:00" }, 
//   "data": { "data1": 1, "data2": "TEST2", "comment": "This is a test!!", 
//        "nameInfo": { "name": "finl", "regiid": "1406163000001" }, 
//        "phoneNumber": [ "010-0000-0000", "010-1111-1111", "010-2222-2222" ] } }

    char *buff = (char *)"{ \"header\": { \"dataSize\": 1000, \"dataType\": \"text\", \"macAddress\": \"00:00:00:00:00\" }, \"data\": { \"data1\": 1, \"data2\": \"TEST2\", \"comment\": \"This is a test!!\", \"nameInfo\": { \"name\": \"finl\", \"regiid\": \"1406163000001\" }, \"phoneNumber\": [ \"010-0000-0000\", \"010-1111-1111\", \"010-2222-2222\" ] } }";
    json_object *myobj, *headerobj, *dataobj;
    json_object *dobj, *dval;
    uint32_t i;
 
    // Read JSON type Data
    myobj = json_tokener_parse(buff);
 
    headerobj = json_object_object_get(myobj, "header");
    dataobj   = json_object_object_get(myobj, "data");
 
    // Parse header Area
    dval = json_object_object_get(headerobj, "dataType");
    DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO, (void *)"dataType : %s\n", json_object_get_string(dval));
    
    dval = json_object_object_get(headerobj, "macAddress");
    DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO, (void *)"macAddress : %s\n", json_object_get_string(dval));
 
    // Parse data area
    dval = json_object_object_get(dataobj, "data1");
    DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO, (void *)"data1 : %d\n", json_object_get_int(dval));
    
    // Parse data.nameInfo area (object in object)
    dobj = json_object_object_get(dataobj, "nameInfo");
    dval = json_object_object_get(dobj, "name");
    DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO, (void *)"nameInfo.name : %s\n", json_object_get_string(dval));
    dval = json_object_object_get(dobj, "regiid");
    DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO, (void *)"nameInfo.regiid : %s\n", json_object_get_string(dval));
    
    // Parse data.phoneNumber (array type)
    dobj = json_object_object_get(dataobj, "phoneNumber");
    DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO, (void *)"nameInfo.phoneNumber is\n");
    for (i = 0; i < json_object_array_length(dobj); i++)
    {
        dval = json_object_array_get_idx(dobj, i);
        DBG_FD_PRINT(fp, DBG_CLI, DBG_INFO, (void *)"   %s\n", json_object_get_string(dval));
    }

    json_object_put(myobj);
}

//
void cli_parser(FILE *fp, uint32_t argc, const char **argv)
{
    if (argc)
    {
        for (const cli_func_t *ptr = cli_root_func; ptr->p_cmd != NULL; ++ptr)
        {
            if(STRCMP_M( argv[0], ptr->p_cmd) == 0)
            {
                ptr->cli_handler(fp, argc-1, (const char **)&argv[1]);
                break;
            }
        }
    }
    else
    {
        //
    }
}

#define CLI_ARG_MAX 10

void cli_strtok_and_run(FILE *fp, char *p_buf)
{
    uint32_t buf_len;
    char *p_buf_cpy;
    char *p_ptr;
    char *argv[CLI_ARG_MAX] ={ NULL, };
    uint32_t argc = 0;

    get_current_rss_monitor(DBG_NONE, (char *)"1");

    buf_len = STRLEN_M(p_buf);
    
    p_buf_cpy = (char *)MALLOC_M(buf_len);    
    STRCPY_M(p_buf_cpy, p_buf);

    p_ptr = strtok(p_buf_cpy, " ");

    while(p_ptr != NULL)
    {
        argv[argc] = p_ptr;
        DBG_FD_PRINT(fp, DBG_CLI, DBG_NONE, (void*)"%s\n", argv[argc]);
        p_ptr = strtok(NULL, " ");

        argc++;

        if (argc >= CLI_ARG_MAX)
        {
            break;
        }
    }

    cli_parser(fp, argc, (const char **)argv);

    FREE_M(p_buf_cpy);

    get_current_rss_monitor(DBG_NONE, (char *)"2");
}

