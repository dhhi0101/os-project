#include "crypto.h"

// 암호화 함수 (128비트 AES, ECB 모드)
// 마스크를 암호화할 때 사용하는 기본적인 암호화 함수
// 입력: plaintext(암호화할 평문), plaintext_len(평문의 길이), key(암호화에 사용할 키), ciphertext (암호화된 결과가 저장될 배열), ciphertext_len (암호화된 데이터의 길이) 
void AES_custom_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *ciphertext, int *ciphertext_len) {
    EVP_CIPHER_CTX *ctx;  // 암호화/복호화 컨텍스트 구조체 포인터
    int len;

    // 입력 데이터 유효성 확인
    if (plaintext == NULL || plaintext_len <= 0 || key == NULL) {
        fprintf(stderr, "Invalid input parameters for encryption\n");
        exit(EXIT_FAILURE);
    }


    // 컨텍스트 생성
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Error creating context for encryption\n");
        // ERR_print_errors_fp(stderr);  : OpenSSL 라이브러리에서 발생한 오류 메시지를 표준 오류 출력(stderr)으로 출력
        ERR_print_errors_fp(stderr); 
        // exit(EXIT_FAILURE);  : 프로그램을 즉시 종료하고, 운영 체제에 비정상 종료 상태(EXIT_FAILURE)를 반환
        exit(EXIT_FAILURE);  // 프로세스가 오류로 인해 종료되었음
    }

    // AES-128 ECB 모드 암호화 작업 초기화
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1) {
        fprintf(stderr, "Error initializing encryption\n");
        ERR_print_errors_fp(stderr);
        // EVP_CIPHER_CTX_free(ctx);  : 작업에 사용된 컨텍스트(EVP_CIPHER_CTX 구조체)를 해제하고, 그에 관련된 모든 자원을 반환
        EVP_CIPHER_CTX_free(ctx);  // 메모리 누수를 방지하기 위해 컨텍스트를 반드시 해제
        exit(EXIT_FAILURE);
    }

    // 패딩 비활성화 
    // 패딩 비활성화 이유
    // - 입력 데이터(키, 마스크, 평문, 암호문)는 항상 16바이트로 고정됨
    // - 패딩을 활성화하면 데이터에 불필요한 패딩이 추가되어 오류 발생 가능
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    // 암호화 수행
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        fprintf(stderr, "Error during encryption\n");
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    *ciphertext_len = len;  // 암호화된 데이터 길이를 ciphertext_len에 저장

    // 최종 블록 처리 
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        fprintf(stderr, "Error finalizing encryption\n");
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    *ciphertext_len += len;  // 최종 블록 길이를 더해 총 암호화된 데이터 길이를 갱신

    // 암호화 컨텍스트 자원 해제
    EVP_CIPHER_CTX_free(ctx);
}

// 복호화 함수 (128비트 AES, ECB 모드)
// 암호화된 마스크를 복호화할 때 사용하는 기본적인 복호화 함수
// 입력: ciphertext (복호화할 암호문), ciphertext_len (암호문의 길이), key (복호화에 사용할 키), plaintext (복호화된 결과가 저장될 배열), plaintext_len (복호화된 데이터의 길이)
void AES_custom_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *plaintext, int *plaintext_len) {
    EVP_CIPHER_CTX *ctx;
    int len;

    // 입력 데이터 유효성 확인
    if (ciphertext == NULL || ciphertext_len <= 0 || key == NULL) {
        fprintf(stderr, "Invalid input parameters for decryption\n");
        exit(EXIT_FAILURE);
    }

    // 컨텍스트 생성
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Error creating context for decryption\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // AES-128 ECB 모드 복호화 작업 초기화
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1) {
        fprintf(stderr, "Error initializing decryption\n");
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // 패딩 비활성화
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    // 복호화 수행
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        fprintf(stderr, "Error during decryption\n");
        ERR_print_errors_fp(stderr);        
        EVP_CIPHER_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    *plaintext_len = len;  // 복호화된 데이터 길이를 plaintext_len에 저장

    // 최종 블록 처리
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        fprintf(stderr, "Error finalizing decryption\n");
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    *plaintext_len += len;  // 최종 블록 길이를 더해 총 복호화된 데이터 길이를 갱신

    // 복호화 컨텍스트 자원 해제
    EVP_CIPHER_CTX_free(ctx);
}


// 마스크 암호화
void AES_encrypt_mask(unsigned char *mask, unsigned char *key, unsigned char *encrypted_mask) {
    int encrypted_mask_len;

    // AES 암호화 수행
    AES_custom_encrypt(mask, KEY_SIZE, key, encrypted_mask, &encrypted_mask_len);
}

// 마스크 복호화
void AES_decrypt_mask(unsigned char *encrypted_mask, unsigned char *key, unsigned char *mask) {
    int mask_len;

    // AES 복호화 수행
    AES_custom_decrypt(encrypted_mask, KEY_SIZE, key, mask, &mask_len);

    if (mask_len != 16) {  // 마스크의 길이가 16바이트인지 확인
        fprintf(stderr, "Decrypted mask length is not 16 bytes: %d\n", mask_len);
    }

}
