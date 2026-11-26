#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define CCSP_BASE_PARAM_LENGTH 4096
#define MAX_SUBSYSTEMPREFIX 256

static char format_s[512];

int test_overflow() {
    int loop1, loop2 = 0, len;
    unsigned int InstNum = 300;
    unsigned int pInstNumList[300];
    for (loop1 = 0; loop1 < InstNum; loop1++) {
        pInstNumList[loop1] = loop1;
    }
    for (loop1 = 0, loop2 = 0; loop1 < (InstNum); loop1++) {
        if (loop2 >= sizeof(format_s) - 20) break;
        len = snprintf((char *)&format_s[loop2], sizeof(format_s) - loop2, "%d,", pInstNumList[loop1]);
        if (len < 0 || loop2 + len >= sizeof(format_s)) break;
        loop2 = loop2 + len;
    }
    if (loop2 >= sizeof(format_s) - 1) {
        return 1;
    }
    format_s[loop2 - 1] = 0;
    return 0;
}

int test_normal() {
    int loop1, loop2 = 0, len;
    unsigned int InstNum = 10;
    unsigned int pInstNumList[10];
    for (loop1 = 0; loop1 < InstNum; loop1++) {
        pInstNumList[loop1] = loop1;
    }
    for (loop1 = 0, loop2 = 0; loop1 < (InstNum); loop1++) {
        if (loop2 >= sizeof(format_s) - 20) break;
        len = snprintf((char *)&format_s[loop2], sizeof(format_s) - loop2, "%d,", pInstNumList[loop1]);
        if (len < 0 || loop2 + len >= sizeof(format_s)) break;
        loop2 = loop2 + len;
    }
    if (loop2 >= sizeof(format_s) - 1) {
        return 1;
    }
    format_s[loop2 - 1] = 0;
    if (strcmp((char *)format_s, "0,1,2,3,4,5,6,7,8,9") != 0) {
        return 1;
    }
    return 0;
}

int main() {
    if (test_normal() != 0) {
        fprintf(stderr, "FAIL: normal case\n");
        return 1;
    }
    if (test_overflow() != 0) {
        fprintf(stderr, "FAIL: overflow case\n");
        return 1;
    }
    printf("PASS: getInstanceIds overflow protection\n");
    return 0;
}
