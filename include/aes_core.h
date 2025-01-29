/**
 * @file aes_core.h
 * @brief Header file for the AES core implementation.
 * 
 * This header file contains the function prototypes and type definitions
 * for the AES implementation.
 * 
 * @version 1.0
 * @date 2025-01-22
 * @author [Your Name]
 * @copyright [Your Copyright Information]
 */

#ifndef AES_CORE
#define AES_CORE

#include <stdint.h>
#define AES_256_KEY_LENGTH 32
#define SUCCESS 0
#define FAILURE -1
#define INVALID_PARAMS_ERROR -101
#include <string.h>
static void * (* const volatile memset_secure)( void *, int, size_t ) = memset;
uint32_t u8array4_to_uint32(const uint8_t a[sizeof(uint32_t)]);

/**
 * @defgroup AES AES Core Implementation
 * @{
 */

//start of aes.h
#include "stdint.h"
# define AES_MAXNR 14
# define AES_BLOCK_SIZE 16
#define AES_GCM_BLOCK_SIZE 16

# define AES_ENCRYPT     1
# define AES_DECRYPT     0

/**
 * @struct aes_key_st
 * @brief Structure to hold the AES key.
 * 
 * This structure contains the round keys and the number of rounds for the AES algorithm.
 */
struct aes_key_st {
# ifdef AES_LONG
    unsigned long rd_key[4 * (AES_MAXNR + 1)];
# else
    unsigned int rd_key[4 * (AES_MAXNR + 1)];
# endif
    int rounds;
};
typedef struct aes_key_st AES_KEY;

/**
 * @brief Set the encryption key for the AES algorithm.
 * 
 * This function sets the encryption key for the AES algorithm.
 * 
 * @param userKey The user-provided key.
 * @param bits The number of bits in the key.
 * @param key The AES key structure to be populated.
 * @return 0 on success, -1 on failure.
 */
int AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);

/**
 * @brief Set the decryption key for the AES algorithm.
 * 
 * This function sets the decryption key for the AES algorithm.
 * 
 * @param userKey The user-provided key.
 * @param bits The number of bits in the key.
 * @param key The AES key structure to be populated.
 * @return 0 on success, -1 on failure.
 */
int AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);

/**
 * @brief Decrypt a block of data using the AES algorithm.
 * 
 * This function decrypts a block of data using the AES algorithm.
 * 
 * @param in The input block to be decrypted.
 * @param out The output block containing the decrypted data.
 * @param key The AES key structure.
 */
void AES_decrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);

/**
 * @brief Encrypt a block of data using the AES algorithm.
 * 
 * This function encrypts a block of data using the AES algorithm.
 * 
 * @param in The input block to be encrypted.
 * @param out The output block containing the encrypted data.
 * @param key The AES key structure.
 */
void AES_encrypt(const unsigned char *in, unsigned char *out,const AES_KEY *key);
# include <stddef.h>
# ifdef  __cplusplus
extern "C" {
# endif


/*
 * Because array size can't be a const in C, the following two are macros.
 * Both sizes are in bytes.
 */

/* This should be a hidden type, but EVP requires that the size be known */


const char *AES_options(void);


//end of aes.h




//start of aes_local.h
# if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_AMD64) || defined(_M_X64))
#  define SWAP(x) (_lrotl(x, 8) & 0x00ff00ff | _lrotr(x, 8) & 0xff00ff00)
#  define GETU32(p) SWAP(*((u32 *)(p)))
#  define PUTU32(ct, st) { *((u32 *)(ct)) = SWAP((st)); }
# else
#  define GETU32(pt) (((u32)(pt)[0] << 24) ^ ((u32)(pt)[1] << 16) ^ ((u32)(pt)[2] <<  8) ^ ((u32)(pt)[3]))
#  define PUTU32(ct, st) { (ct)[0] = (u8)((st) >> 24); (ct)[1] = (u8)((st) >> 16); (ct)[2] = (u8)((st) >>  8); (ct)[3] = (u8)(st); }
# endif

typedef uint64_t u64;
# ifdef AES_LONG
typedef unsigned long u32;
# else
typedef unsigned int u32;
# endif
typedef unsigned short u16;
typedef unsigned char u8;

# define MAXKC   (256/32)
# define MAXKB   (256/8)
# define MAXNR   14
//end of aes_local.h


/**
 * @brief Encrypts plaintext using AES-256 in GCM mode.
 * 
 * @param key The encryption key.
 * @param iv The initialization vector.
 * @param iv_length The length of the initialization vector.
 * @param plaintext The plaintext to be encrypted.
 * @param plaintext_length The length of the plaintext.
 * @param aad The additional authenticated data.
 * @param aad_length The length of the additional authenticated data.
 * @param ciphertext The resulting ciphertext.
 * @param auth_tag Optional authentication tag. Pass NULL to skip authentication.
 * @return The result of the encryption.
 */
int16_t aes256_gcm_encrypt(
        const uint8_t key[AES_256_KEY_LENGTH],
        const uint8_t * const iv,
        const uint16_t iv_length,
        const uint8_t * const plaintext,
        const uint64_t plaintext_length,
        const uint8_t * const aad,
        const uint64_t aad_length,
        uint8_t * const ciphertext,
        uint8_t *auth_tag);

/**
 * @brief Decrypts ciphertext using AES-256 in GCM mode without authentication verification.
 * 
 * @param key The encryption key.
 * @param iv The initialization vector.
 * @param iv_length The length of the initialization vector.
 * @param ciphertext The ciphertext to be decrypted.
 * @param ciphertext_length The length of the ciphertext.
 * @param aad The additional authenticated data.
 * @param aad_length The length of the additional authenticated data.
 * @param plaintext The resulting plaintext.
 * @return The result of the decryption.
 */
int16_t aes256_gcm_decrypt(
        const uint8_t  key[AES_256_KEY_LENGTH],
        const uint8_t * const iv,
        const uint16_t iv_length,
        const uint8_t * const ciphertext,
        const uint64_t ciphertext_length,
        const uint8_t * const aad,
        const uint64_t aad_length,
        uint8_t * const plaintext);

/**
 * @brief Encrypts plaintext using AES-256 in ECB mode.
 * 
 * @param key The encryption key (must be 32 bytes for AES-256).
 * @param plaintext The input plaintext to encrypt.
 * @param plaintext_len Length of the plaintext.
 * @param ciphertext Output buffer for the encrypted data.
 * @return int Returns 0 on success, negative value on error.
 */
int aes256_ecb_encrypt(const unsigned char *key, const unsigned char *plaintext, size_t plaintext_len, unsigned char *ciphertext);

/**
 * @brief Decrypts ciphertext using AES-256 in ECB mode.
 * 
 * @param key The encryption key (must be 32 bytes for AES-256).
 * @param ciphertext The input ciphertext to decrypt.
 * @param ciphertext_len Length of the ciphertext.
 * @param plaintext Output buffer for the decrypted data.
 * @return int Returns 0 on success, negative value on error.
 */
int aes256_ecb_decrypt(const unsigned char *key, const unsigned char *ciphertext, size_t ciphertext_len, unsigned char *plaintext);

/**
 * @}
 */

#endif /* AES_CORE */