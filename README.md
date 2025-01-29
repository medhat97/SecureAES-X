# AES Encryption Standalone Library

## Overview
This project is a standalone implementation of AES encryption extracted from the OpenSSL project, supporting both ECB and GCM modes of operation. It provides a lightweight, efficient implementation of AES encryption for educational and practical purposes.

## Origin
The core AES implementation (`aes_core.c`) is derived from the OpenSSL project, with modifications to create a standalone library.

## Features
- AES ECB Mode Encryption/Decryption
- AES GCM Mode Encryption/Decryption
- Performance Benchmarking

## Prerequisites
- GCC or Clang compiler
- Make utility

## Building the Project
```bash
make
```

## Running Tests
```bash
make test
```

## Performance Benchmarks
Run the speed test to measure AES GCM encryption performance:
```bash
make benchmark
```

## License
Please refer to the OpenSSL licensing terms for the core AES implementation.

## Contributing
Contributions are welcome. Please submit pull requests or open issues on the GitHub repository.

## Author
[Your Name]
