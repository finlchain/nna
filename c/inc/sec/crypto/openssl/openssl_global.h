/**
    @file openssl_global.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __OPENSSL_GLOBAL_H__
#define __OPENSSL_GLOBAL_H__

//#ifdef __cplusplus
//extern "C"
//{
//#endif

#define OPENSSL_102    DISABLED // ENABLED DISABLED
#define OPENSSL_111    ENABLED // ENABLED DISABLED

#define X25519_PRIVATE_KEY_LEN_ 32
#define X25519_PUBLIC_KEY_LEN_ 32
#define X25519_SHARED_KEY_LEN_ 32

#define ED25519_PRIVATE_KEY_LEN_ 64
#define ED25519_PUBLIC_KEY_LEN_ 32
#define ED25519_SIGNATURE_LEN_ 64


// OPENSSL
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>

// OpenSSL user defined
#include "openssl_util.h"

#include "openssl_rsa.h"

#include "openssl_ec.h"
#include "openssl_ecdsa.h"
#include "openssl_ecies.h"

#include "openssl_25519.h"
#include "openssl_curve25519.h"
#include "openssl_ed25519.h"
#include "openssl_x25519.h"

//#ifdef __cplusplus
//}
//#endif

#endif /* __OPENSSL_GLOBAL_H__ */
