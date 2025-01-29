/*
 * @file benchmark_speed_test.c
 * @brief Benchmarking AES encryption performance.
 * 
 * This file contains code to benchmark the performance of the AES
 * encryption functions. It measures the time taken to encrypt
 * a specified amount of data using both ECB and GCM modes.
 * 
 * @version 1.0
 * @date 2025-01-22
 */

#include "aes_core.h"
#include <stdio.h>
#include <stdint.h>

/**
 * Returns the CPU cycles at the start of a measurement.
 *
 * This function uses the RDTSC instruction to read the timestamp counter.
 * The result is a 64-bit value representing the number of CPU cycles since
 * the processor was reset.
 */
inline static uint64_t getStartTimeInCycles(void)
{
    unsigned high, low;
    __asm__ __volatile__("CPUID\n\t"
                         "RDTSC\n\t"
                         "mov %%edx, %0\n\t"
                         "mov %%eax, %1\n\t"
                         : "=r"(high), "=r"(low)
                         :
                         : "%rax", "%rbx", "%rcx", "%rdx");

    return ((uint64_t)low) ^ (((uint64_t)high) << 32);
}

/**
 * Returns the CPU cycles at the stop of a measurement.
 *
 * This function uses the RDTSCP instruction to read the timestamp counter.
 * The result is a 64-bit value representing the number of CPU cycles since
 * the processor was reset.
 */
inline static uint64_t getStopTimeInCycles(void)
{
    unsigned high, low;
    __asm__ __volatile__("RDTSCP\n\t"
                         "mov %%edx, %0\n\t"
                         "mov %%eax, %1\n\t"
                         "CPUID\n\t"
                         : "=r"(high), "=r"(low)
                         :
                         : "%rax", "%rbx", "%rcx", "%rdx");

    return ((uint64_t)low) ^ (((uint64_t)high) << 32);
}


int main()
{
    // Record the start time of the benchmark
    uint64_t startTimeInCycles, stopTimeInCycles = 0;

    startTimeInCycles = getStartTimeInCycles();

    // Perform the benchmark for 1 million iterations
    for(int iteration = 0; iteration < 1000000; ++iteration)
    {
        // Define the plaintext to be encrypted
        uint8_t plaintext[] = "this is a sample plaintext hello Gebril, this is medhat,introduce yourself!";
        
        // Define the encryption key
        uint8_t encryptionKey[32] = 
        {
            0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81,
            0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25 
        };
        
        // Define the initialization vector
        uint8_t initializationVector[12] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12};
        uint16_t initializationVectorLength = 12;
        
        // Define the length of the plaintext
        uint64_t plaintextLength = 75; // Excluding null terminator
        
        // Define the additional authenticated data
        uint8_t additionalAuthenticatedData[] = "Additional data for authentication.";
        uint64_t additionalAuthenticatedDataLength = sizeof(additionalAuthenticatedData); // Excluding null terminator

        // Placeholder arrays for ciphertext and decrypted text
        uint8_t ciphertext[75];
        uint8_t decryptedText[75];
        
        // Perform the encryption
        aes256_gcm_encrypt(encryptionKey, initializationVector, initializationVectorLength, plaintext, plaintextLength, additionalAuthenticatedData, additionalAuthenticatedDataLength, ciphertext, NULL);
        
        // Perform the decryption without authentication
        int decryptionStatus = aes256_gcm_decrypt(encryptionKey, initializationVector, initializationVectorLength, ciphertext, plaintextLength, additionalAuthenticatedData, additionalAuthenticatedDataLength, decryptedText);
        if (decryptionStatus != SUCCESS) {
            printf("Decryption failed with status: %d\n", decryptionStatus);
            return 1;
        }
    }

    // Record the stop time of the benchmark
    stopTimeInCycles = getStopTimeInCycles();
    
    // Print the benchmark result
    printf("Benchmark = %lu\n", stopTimeInCycles - startTimeInCycles);
}
