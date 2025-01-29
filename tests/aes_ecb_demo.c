/*
 * @file aes_ecb_demo.c
 * @brief Demonstration of AES encryption in ECB mode.
 * 
 * This file provides a simple demonstration of how to use the AES
 * encryption functions in ECB mode. It includes example plaintext
 * and key, and outputs the encrypted ciphertext.
 * 
 * @version 1.0
 * @date 2025-01-22
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "aes_core.h"

/**
 * @brief Prints a hexadecimal representation of a byte array.
 * 
 * @param label A label to print before the hexadecimal output.
 * @param data The byte array to print.
 * @param len The length of the byte array.
 */
void print_hex(const char* label, const unsigned char* data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    // Example key and plaintext
    unsigned char key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                              0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                              0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                              0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    uint8_t plaintext[] = "This is a secure message for encryption testing.";
    uint8_t ciphertext[sizeof(plaintext)];

    // Perform AES ECB encryption
    int result = aes256_ecb_encrypt(key, plaintext, sizeof(plaintext) - 1, ciphertext);
    if (result != 0) {
        printf("Encryption failed!\n");
        return -1;
    }

    // Output the results
    print_hex("Plaintext", plaintext, sizeof(plaintext) - 1);
    print_hex("Ciphertext", ciphertext, sizeof(ciphertext));

    return 0;
}