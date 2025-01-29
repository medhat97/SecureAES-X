/**
 * @file gcm.c
 * @brief Implementation of GCM (Galois/Counter Mode) for AES.
 * 
 * This file provides the functions necessary for AES encryption and
 * decryption in GCM mode, including functions for handling the
 * initialization vector and authentication tags.
 * 
 * @version 1.0
 * @date 2025-01-22
 */

#include "../include/gcm.h"
#include "../include/aes_core.h"

/**
 * @brief Multiplies two 128-bit numbers in GF(2^128).
 * 
 * This function performs the multiplication of two 128-bit numbers in the
 * finite field GF(2^128) using the irreducible polynomial x^127 + x^7 + x^2 + x + 1.
 * 
 * @param a The first 128-bit number.
 * @param b The second 128-bit number.
 * @param c The result of the multiplication.
 */
void aes_gcm_gf_128_mul(const uint8_t a[sizeof(__int128)], const uint8_t b[sizeof(__int128)], uint8_t c[sizeof(__int128)]);

/**
 * @brief Performs a bitwise XOR operation on two blocks.
 * 
 * This function performs a bitwise XOR operation on two blocks of size AES_GCM_BLOCK_SIZE.
 * 
 * @param a The first block.
 * @param b The second block.
 * @param c The result of the XOR operation.
 */
static inline void xor_block(
        const uint8_t a[AES_GCM_BLOCK_SIZE],
        const uint8_t b[AES_GCM_BLOCK_SIZE],
              uint8_t c[AES_GCM_BLOCK_SIZE])
{
    for(int i=0; i<AES_GCM_BLOCK_SIZE; i++){
        c[i] = a[i] ^ b[i];
    }
}

/**
 * @brief Converts a 16-byte array to a 128-bit integer.
 * 
 * This function converts a 16-byte array to a 128-bit integer.
 * 
 * @param a The 16-byte array.
 * @return The 128-bit integer.
 */
static inline unsigned __int128 u8array16_to_int128(const uint8_t a[AES_GCM_BLOCK_SIZE])
{
    unsigned __int128 b = 0;
    for(uint16_t i = 0; i < sizeof(__int128); i++) {
        b = (b << 8) | a[sizeof(__int128)-1-i];
    }
    return b;
}

/**
 * @brief Converts a 128-bit integer to a 16-byte array.
 * 
 * This function converts a 128-bit integer to a 16-byte array.
 * 
 * @param a The 128-bit integer.
 * @param b The 16-byte array.
 */
static inline void int128_to_u8array16(unsigned __int128 a, uint8_t b[AES_GCM_BLOCK_SIZE])
{
    for(uint16_t i = 0; i < sizeof(__int128); i++) {
        b[sizeof(__int128)-1-i] = (uint8_t)(a & 0xFF);
        a >>= 8;
    }
}

/**
 * @brief Converts a 64-bit integer to an 8-byte array.
 * 
 * This function converts a 64-bit integer to an 8-byte array.
 * 
 * @param a The 64-bit integer.
 * @param b The 8-byte array.
 */
static inline void uint64_to_u8array8(uint64_t a, uint8_t b[sizeof(uint64_t)])
{
    for(int16_t i=sizeof(uint64_t)-1; i>=0;i--) {
        b[i] = (uint8_t)(a & 0xffu);
        a >>= 8u;
    }
}

/**
 * @brief Converts a 32-bit integer to a 4-byte array.
 * 
 * This function converts a 32-bit integer to a 4-byte array.
 * 
 * @param a The 32-bit integer.
 * @param b The 4-byte array.
 */
static inline void uint32_to_u8array4(uint32_t a, uint8_t b[sizeof(uint32_t)])
{
    for(int16_t i=sizeof(uint32_t)-1; i>=0;i--) {
        b[i] = (uint8_t)(a & 0xffu);
        a >>= 8u;
    }
}

/**
 * @brief Converts two lengths to a 16-byte array.
 * 
 * This function converts two lengths to a 16-byte array, where each length is
 * multiplied by 8 before being converted.
 * 
 * @param bytelen1 The first length.
 * @param bytelen2 The second length.
 * @param c The 16-byte array.
 */
static inline void lengths_to_u8array16(uint64_t bytelen1, uint64_t bytelen2, uint8_t c[AES_GCM_BLOCK_SIZE])
{
    uint64_to_u8array8(bytelen1<<3u, c);
    uint64_to_u8array8(bytelen2<<3u, &c[sizeof(uint64_t)]);
}

/**
 * @brief Increments a 32-bit counter.
 * 
 * This function increments a 32-bit counter.
 * 
 * @param counter The 32-bit counter.
 */
static void increment_32_bit_counter(uint8_t counter[sizeof(uint32_t)])
{
    uint32_t count = u8array4_to_uint32(counter);
    count += 1;
    uint32_to_u8array4(count, counter);
}

/**
 * @brief Computes the GHASH of a block.
 * 
 * This function computes the GHASH of a block using the provided key and
 * authentication tag.
 * 
 * @param H The key.
 * @param a The block.
 * @param a_length The length of the block.
 * @param hash The authentication tag.
 * @param tmp_block A temporary block.
 */
static inline void ghash_internal(const uint8_t *H, const uint8_t *a, const uint64_t a_length, uint8_t *hash, uint8_t *tmp_block) {
    uint64_t block_count = a_length / AES_GCM_BLOCK_SIZE;
    uint64_t index = 0;
    for (uint64_t i = 0; i < block_count; i++) {
        xor_block(hash, &a[index], hash);
        aes_gcm_gf_128_mul(H, hash, hash);
        index += AES_GCM_BLOCK_SIZE;
    }
    uint64_t bytes_remaining = a_length % AES_GCM_BLOCK_SIZE;
    if (bytes_remaining) {
        for (uint64_t i = 0; i < AES_GCM_BLOCK_SIZE; i++) {
            tmp_block[i] = i < bytes_remaining ? a[index + i] : 0;
        }
        xor_block(hash, tmp_block, hash);
        aes_gcm_gf_128_mul(H, hash, hash);
    }
}

/**
 * @brief Computes the GHASH of two blocks.
 * 
 * This function computes the GHASH of two blocks using the provided key and
 * authentication tag.
 * 
 * @param H The key.
 * @param a The first block.
 * @param a_length The length of the first block.
 * @param b The second block.
 * @param b_length The length of the second block.
 * @param hash The authentication tag.
 */
static void ghash(const uint8_t *H,
                  const uint8_t * const a, const uint64_t a_length,
                  const uint8_t * const b, const uint64_t b_length,
                  uint8_t *hash)
{
    uint8_t tmp_block[AES_GCM_BLOCK_SIZE];
    memset_secure(hash, 0, AES_GCM_BLOCK_SIZE);

    // Process AAD
    if (a != NULL && a_length > 0) {
        ghash_internal(H, a, a_length, hash, tmp_block);
    }

    // Process ciphertext
    if (b != NULL && b_length > 0) {
        ghash_internal(H, b, b_length, hash, tmp_block);
    }

    // Process lengths (in bits)
    uint64_t a_bits = a_length * 8;
    uint64_t b_bits = b_length * 8;
    
    // Store lengths in big-endian format
    for (int i = 0; i < 8; i++) {
        tmp_block[i] = (a_bits >> ((7-i) * 8)) & 0xFF;
        tmp_block[i+8] = (b_bits >> ((7-i) * 8)) & 0xFF;
    }

    xor_block(hash, tmp_block, hash);
    aes_gcm_gf_128_mul(H, hash, hash);
}

/**
 * @brief Encrypts a block using AES-256-GCM.
 * 
 * This function encrypts a block using AES-256-GCM.
 * 
 * @param key The encryption key.
 * @param iv The initialization vector.
 * @param iv_length The length of the initialization vector.
 * @param plaintext The plaintext to be encrypted.
 * @param plaintext_length The length of the plaintext.
 * @param aad The additional authenticated data.
 * @param aad_length The length of the additional authenticated data.
 * @param ciphertext The ciphertext.
 * @param auth_tag The authentication tag.
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
        uint8_t auth_tag[AES_GCM_BLOCK_SIZE])
{
    uint64_t index = 0;
    uint64_t block_count = 0;
    static uint8_t initial_count[4] = { 0, 0, 0, 1 };
    static uint8_t zero_block[AES_GCM_BLOCK_SIZE] = { 0 };
    uint8_t eky0[AES_GCM_BLOCK_SIZE] = { 0 };
    uint8_t key_stream[AES_GCM_BLOCK_SIZE] = { 0 };
    uint8_t hash[AES_GCM_BLOCK_SIZE] = { 0 };
    uint16_t bytes_remaining = 0;
    uint8_t ctrblk[AES_GCM_BLOCK_SIZE] = { 0 };
    uint8_t h[AES_GCM_BLOCK_SIZE];

    if((key == NULL) ||
       (iv_length > 0 && iv == NULL) ||
       (plaintext_length > 0 && plaintext == NULL) ||
       (plaintext_length > 0 && ciphertext == NULL) ||
       (aad_length > 0 && aad == NULL) ){
        return -101;
    }

    // Initialize AES key
    AES_KEY enc_key;
    AES_set_encrypt_key(key, 256, &enc_key);
    
    // Generate hash subkey H = E(K, 0^128)
    AES_encrypt(zero_block, h, &enc_key);

    // Initialize counter block
    if(iv_length == 12) { // 96-bit IV is handled differently
        memcpy(ctrblk, iv, 12);
        memcpy(ctrblk + 12, initial_count, 4);
    } else {
        // If IV is not 96 bits, use GHASH
        ghash(h, NULL, 0, iv, iv_length, ctrblk);
    }

    // Generate initial counter block for auth tag (J0)
    memcpy(eky0, ctrblk, AES_GCM_BLOCK_SIZE);
    
    // Increment counter for encryption (J1)
    increment_32_bit_counter(&ctrblk[12]);

    // Process full blocks
    block_count = plaintext_length / AES_GCM_BLOCK_SIZE;
    index = 0;
    for(uint64_t count = 0; count < block_count; count++) {
        AES_encrypt(ctrblk, key_stream, &enc_key);
        xor_block(&plaintext[index], key_stream, &ciphertext[index]);
        increment_32_bit_counter(&ctrblk[12]);
        index += AES_GCM_BLOCK_SIZE;
    }

    // Process final partial block if any
    bytes_remaining = plaintext_length % AES_GCM_BLOCK_SIZE;
    if(bytes_remaining) {
        AES_encrypt(ctrblk, key_stream, &enc_key);
        for (uint16_t i = 0; i < bytes_remaining; i++) {
            ciphertext[index + i] = plaintext[index + i] ^ key_stream[i];
        }
    }

    // Generate authentication tag if requested
    if (auth_tag != NULL) {
        ghash(h, aad, aad_length, ciphertext, plaintext_length, hash);
        AES_encrypt(eky0, key_stream, &enc_key);
        xor_block(hash, key_stream, auth_tag);
    }

    return SUCCESS;
}

/**
 * @brief Decrypts a block using AES-256-GCM without authentication.
 * 
 * This function decrypts a block using AES-256-GCM without verifying the authentication tag.
 * 
 * @param key The encryption key.
 * @param iv The initialization vector.
 * @param iv_length The length of the initialization vector.
 * @param ciphertext The ciphertext to be decrypted.
 * @param ciphertext_length The length of the ciphertext.
 * @param aad The additional authenticated data.
 * @param aad_length The length of the additional authenticated data.
 * @param plaintext The plaintext.
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
        uint8_t * const plaintext)
{
    if((key == NULL) ||
       (iv_length > 0 && iv == NULL) ||
       (ciphertext_length > 0 && plaintext == NULL) ||
       (ciphertext_length > 0 && ciphertext == NULL) ||
       (aad_length > 0 && aad == NULL) ){

        return INVALID_PARAMS_ERROR;
    }

    uint16_t i;
    uint64_t index = 0;
    uint64_t block_count = 0;
    static uint8_t initial_count[4] = { 0, 0, 0, 1 };
    static uint8_t zero_block[AES_GCM_BLOCK_SIZE] = { 0 };
    uint8_t eky0[AES_GCM_BLOCK_SIZE] = { 0 };
    uint8_t key_stream[AES_GCM_BLOCK_SIZE] = { 0 };
    uint16_t bytes_remaining = 0;
    uint8_t ctrblk[AES_GCM_BLOCK_SIZE];
    uint8_t h[AES_GCM_BLOCK_SIZE];

    AES_KEY enc_key;
    AES_set_encrypt_key(key, 256, &enc_key);
    AES_encrypt(zero_block, h, &enc_key);

    if(iv_length != AES_GCM_IV_LENGTH_IN_BYTES){
        ghash(h, NULL, 0, iv, iv_length, ctrblk);
    } else {
        for(i=0; i<4; i++){
            ctrblk[i]    = iv[i];
            ctrblk[4+i]  = iv[4+i];
            ctrblk[8+i]  = iv[8+i];
            ctrblk[12+i] = initial_count[i];
        }
    }
    
    memcpy(eky0, ctrblk, AES_GCM_BLOCK_SIZE);
    increment_32_bit_counter(&ctrblk[AES_GCM_COUNTER_OFFSET]);

    block_count = ciphertext_length / AES_GCM_BLOCK_SIZE;
    index=0;
    for(uint64_t count=0; count<block_count; count++){
        AES_encrypt(ctrblk, key_stream, &enc_key);
        xor_block(&ciphertext[index], key_stream, &plaintext[index]);
        increment_32_bit_counter(&ctrblk[AES_GCM_COUNTER_OFFSET]);
        index += AES_GCM_BLOCK_SIZE;
    }
    bytes_remaining = ciphertext_length % AES_GCM_BLOCK_SIZE;
    if(bytes_remaining){
        AES_encrypt(ctrblk, key_stream, &enc_key);
        for (i = 0; i < bytes_remaining; i++) {
            plaintext[index+i] = ciphertext[index+i] ^ key_stream[i];
        }
    }

    return SUCCESS;
}

/**
 * @brief Multiplies two 128-bit numbers in GF(2^128).
 * 
 * This function performs the multiplication of two 128-bit numbers in the
 * finite field GF(2^128) using the irreducible polynomial x^127 + x^7 + x^2 + x + 1.
 * 
 * @param a The first 128-bit number.
 * @param b The second 128-bit number.
 * @param c The result of the multiplication.
 */
void aes_gcm_gf_128_mul(const uint8_t a[sizeof(__int128)], const uint8_t b[sizeof(__int128)], uint8_t c[sizeof(__int128)])
{
    unsigned __int128 x = u8array16_to_int128(a);
    unsigned __int128 y = u8array16_to_int128(b);
    unsigned __int128 z = 0;
    unsigned __int128 r = 0;
    
    for (int i = 127; i >= 0; i--) {
        if (y & ((unsigned __int128)1 << i)) {
            z ^= x;
        }
        r = x & 1;
        x >>= 1;
        if (r) {
            x ^= (((unsigned __int128)0x87) << 120);  // x^7 + x^2 + x + 1 when reducing by x^128 + x^7 + x^2 + x + 1
        }
    }
    
    int128_to_u8array16(z, c);
}
