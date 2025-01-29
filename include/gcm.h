/**
 * @file gcm.h
 * @brief Header file for GCM mode implementation.
 * 
 * This header file contains the function prototypes and type definitions
 * for the GCM mode implementation.
 * 
 * @version 1.0
 * @date 2025-01-22
 * 
 * @defgroup GCM GCM Mode Implementation
 * @{
 */

#ifndef AES_GCM_H
#define AES_GCM_H

#include "aes_core.h"
#include <stdint.h>
#include <string.h>

#define AES_GCM_BLOCK_SIZE 16
#define AES_GCM_IV_LENGTH_IN_BITS   96
#define AES_GCM_IV_LENGTH_IN_BYTES  12
#define AES_GCM_COUNTER_OFFSET      12

/**
 * @defgroup AES256GCM AES256 GCM Mode
 * @{
 */

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
 * @}
 */

/**
 * @}
 */

#endif // AES_GCM_H
