#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdio.h>  // 표준 입출력 함수 사용 (printf, fprintf, FILE 등)
#include <stdlib.h> // 표준 라이브러리 함수 사용 (malloc, free, exit 등)
#include <string.h> // 문자열 처리 함수 사용 (strncpy, strcmp, strlen 등)
// OpenSSL 헤더 파일
#include <openssl/evp.h>  // OpenSSL의 암호화/복호화 관련 함수 (EVP 인터페이스)
#include <openssl/rand.h> // OpenSSL의 난수 생성 함수 (RAND_bytes 등)
#include <openssl/err.h>  // OpenSSL의 오류 처리 함수 (ERR_print_errors_fp 등)

#define KEY_SIZE 16 // AES-128의 키 크기

// AES 암호화 함수
void AES_custom_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *ciphertext, int *ciphertext_len);

// AES 복호화 함수
void AES_custom_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *plaintext, int *plaintext_len);

// 마스크 암호화
void AES_encrypt_mask(unsigned char *mask, unsigned char *key, unsigned char *encrypted_mask);

// 마스크 복호화
void AES_decrypt_mask(unsigned char *encrypted_mask, unsigned char *key, unsigned char *mask);

#endif 
