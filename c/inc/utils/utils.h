/**
    @file utils.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __UTILS_H__
#define __UTILS_H__

#ifdef __cplusplus
extern "C"
{
#endif

#define IP_STR_SIZE 20
#define PORT_PRTCL_STR_SIZE 10

#define FWD_STR_SIZE 1024

typedef struct 
{
#if (UTIL_CRC_ALGO_2 == ENABLED)
    uint32_t crc_table[UTIL_CRC_TABLE_SIZE];
#endif // UTIL_CRC_ALGO_2
} UTIL_CNTX_T;

//
extern UTIL_CNTX_T *util_get_cntx(void);
extern void util_init(bool b_init);

#if (defined (_WIN32) || defined (_WIN64))
extern void usleep(DWORD waitTime);
#endif // _WIN32 || _WIN64

//
extern void util_system(char *p_fwd);
extern size_t util_fread(void *ptr, size_t size, size_t count, FILE *stream);
extern char *util_fgets(char *s, int n, FILE *stream);

//
extern void util_rand_init(void);

// firewall-cmd
extern void util_init_fwd(void);
extern void util_reload_fwd(void);
extern void util_update_fwd_source(in_addr_t ip_addr);
extern void util_update_fwd_source_port(uint16_t port, bool tcp);
extern void util_update_fwd_rich_rule(in_addr_t src_ip_addr, uint16_t src_port, in_addr_t dst_ip_addr, uint16_t dst_port, bool tcp);

//
extern void util_time_update(void);
//
extern uint64_t util_curtime_ms (void);
extern uint64_t util_curtime_us (void);
extern void util_current_time_with_ms (uint64_t *p_utc_ms);
extern void util_current_time_with_us (uint64_t *p_utc_us);

//
extern int32_t util_hex2str(unsigned char *in, int inlen, char *out, int *outlen);
extern int32_t util_str2hex(const char *in, unsigned char *out, int *outlen);
extern int32_t util_str2hex_temp(const char *in, unsigned char *out, int outlen, bool reversed);
extern int32_t util_hex2str_temp(unsigned char *in, int inlen, char *out, int outlen, bool reversed);

//
#if (UTIL_CRC_ALGO_1 == ENABLED)
extern uint32_t util_crc32a(unsigned char *p_msg, uint32_t msg_len);
#endif // UTIL_CRC_ALGO_1

#if (UTIL_CRC_ALGO_2 == ENABLED)
extern void util_make_crc_table(uint32_t crc_table[]);
extern uint32_t util_crc32b(unsigned char *p, uint32_t n, uint32_t crc_table[]);
#endif // UTIL_CRC_ALGO_2
// Calculated CRC32
uint32_t util_cal_crc32(unsigned char *p, uint32_t n);
// Check CRC32
extern int32_t util_chk_crc32(unsigned char *p, uint32_t n);

//
extern void util_get_my_ip_addr(void);
extern int32_t util_is_my_ip_addr(in_addr_t ip_addr);
extern void util_cpu_serial_info(void);
extern void util_hdd_serial_info(void);
extern void util_bios_serial_info(void);
extern uint32_t util_bios_uuid_info(uint8_t **p_bios_sn);

//
extern int32_t util_create_dir(const char *fdir);
extern int32_t util_exists_dir(const char *fdir);
extern int32_t util_remove_dir(const char *fdir);
extern int32_t util_exists_file(const char *fname);
extern int32_t util_remove_file(const char *fname);
extern int32_t util_exists_fd(int32_t fd);

//
extern int32_t util_file_w(char *p_path, uint8_t *p_buf, uint32_t buf_len);
extern int32_t util_file_a(char *p_path, uint8_t *p_buf, uint32_t buf_len);
extern char *util_file_r(char *p_path, uint32_t *p_buf_len);
//
extern int32_t util_hex_file_wb(char *p_path, uint8_t *p_buf, uint32_t buf_len);
extern char *util_hex_file_rb(char *p_path, uint32_t *p_buf_len);

//
extern char *util_slice_str(const char *p_str, uint32_t start, uint32_t end);

//
extern int32_t util_str_upper_case(char *p_str, uint32_t len);
extern int32_t util_str_lower_case(char *p_str, uint32_t len);

//
extern double util_round_up(double val, uint32_t f_p);
extern double util_round_down(double val, uint32_t f_p);

#ifdef __cplusplus
}
#endif

#endif /* __UTILS_H__ */

