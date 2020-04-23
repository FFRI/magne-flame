#include <stdio.h>
#include <string.h>
#include <Windows.h>

#define CHECK(i, b) (len>(i)&&str[(i)]==(b))

int vuln(const char* argv0, const char* str) {
    char* pNull = NULL;
    const size_t len = strlen(str);
    if (CHECK(0, 'C')) {
        printf("C");
        if (CHECK(1, 'R')) {
            printf("R");
            if (CHECK(2, 'A')) {
                printf("A");
                if (CHECK(3, 'S')) {
                    printf("S");
                    if (CHECK(4, 'H')) {
                        printf("H");
                        printf("CRASH!\n");
                        *pNull = 4649;
                        return 2;
                    }
                }
            }
        }
    }

    printf("%s: %s\n", argv0, str);
    return 0;
}

int main(int argc, char** argv) {
    if (argc <= 1) {
        printf("./%s [input]\n", argv[0]);
        printf("input==\"CRASH\"\n");
        return 1;
    }

    return vuln(argv[0], argv[1]);
}
