/*
 * @file aes_gcm_demo.c
 * @brief Demonstration of AES encryption in GCM mode.
 * 
 * This file provides a simple demonstration of how to use the AES
 * encryption functions in GCM mode. It includes example plaintext,
 * key, and additional authenticated data, and outputs the encrypted
 * ciphertext and authentication tag.
 * 
 * @version 1.0
 * @date 2025-01-22
 */

#include "aes_core.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

int main() {
    // Test vector key and plaintext
    unsigned char key[] = {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
    };

    unsigned char iv[] = {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88
    };

    unsigned char aad[] = {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2
    };

    unsigned char plaintext[] = {
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
        0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
        0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
        0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
        0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55
    };
    
    unsigned char ciphertext[sizeof(plaintext)];
    unsigned char decryptedtext[sizeof(plaintext)];
    unsigned char auth_tag[AES_GCM_BLOCK_SIZE];

    // Perform AES GCM encryption
    printf("Performing AES-GCM encryption...\n");
    int result = aes256_gcm_encrypt(key, iv, sizeof(iv), plaintext, sizeof(plaintext), aad, sizeof(aad), ciphertext, auth_tag);
    if (result != 0) {
        printf("Encryption failed!\n");
        return -1;
    }

    // Output the results
    printf("\nPlaintext:\n");
    for (size_t i = 0; i < sizeof(plaintext); ++i) {
        printf("%02x", plaintext[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    printf("AAD:\n");
    for (size_t i = 0; i < sizeof(aad); ++i) {
        printf("%02x", aad[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    printf("Ciphertext:\n");
    for (size_t i = 0; i < sizeof(ciphertext); ++i) {
        printf("%02x", ciphertext[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    printf("Authentication Tag (optional):\n");
    for (size_t i = 0; i < AES_GCM_BLOCK_SIZE; ++i) {
        printf("%02x", auth_tag[i]);
    }
    printf("\n\n");

    // Perform AES GCM decryption without verification
    printf("Performing AES-GCM decryption without verification...\n");
    result = aes256_gcm_decrypt(key, iv, sizeof(iv), ciphertext, sizeof(ciphertext), aad, sizeof(aad), decryptedtext);
    if (result != 0) {
        printf("Decryption failed!\n");
        return -1;
    }

    printf("Decrypted text:\n");
    for (size_t i = 0; i < sizeof(decryptedtext); ++i) {
        printf("%02x", decryptedtext[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    // Verify decryption was successful
    if (memcmp(plaintext, decryptedtext, sizeof(plaintext)) == 0) {
        printf("Success: Decrypted text matches original plaintext!\n");
    } else {
        printf("Error: Decrypted text does not match original plaintext!\n");
        return -1;
    }

    return 0;
}
