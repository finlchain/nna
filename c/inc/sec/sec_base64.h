/**
    @file sec_base64.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __SEC_BASE64_H__
#define __SEC_BASE64_H__

/* c */
extern int32_t b64_encode(const uint8_t *p_buf, size_t length, char **pp_b64_text);
extern int32_t b64_decode(char *p_b64_msg, uint8_t **pp_buf, size_t *p_length);

#endif // __SEC_BASE64_H__

