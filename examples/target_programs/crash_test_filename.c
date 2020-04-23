#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <Windows.h>

#define CHECK(c, b) (fread(&c,1,sizeof(char),fp)==1&&c==(b)&&printf("%c",c))

int vuln(char** argv) {
    char* pNull = NULL;
    FILE* fp = fopen(argv[1], "r");
    if (!fp) {
        printf("Couldn't open %s\n", argv[1]);
        return 1;
    }

    char c;
    if (CHECK(c, 'C')) {
        printf("C");
        if (CHECK(c, 'R')) {
            printf("R");
            if (CHECK(c, 'A')) {
                printf("A");
                if (CHECK(c, 'S')) {
                    printf("S");
                    if (CHECK(c, 'H')) {
                        printf("H");
                        printf("\nCRASH!\n");
                        *pNull = 4649;
                        return 2;
                    }
                }
            }
        }
    }

    printf("\n");
    fclose(fp);
    return 0;
}

int main(int argc, char** argv) {
    if (argc <= 1) {
        printf("./%s [input file]\n", argv[0]);
        printf("input==\"CRASH\"\n");
        return 1;
    }

    return vuln(argv);
}
