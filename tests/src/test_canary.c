#include <stdlib.h>
#include <stdio.h>
#include <string.h>


int main(int argc, char ** argv) {
    char buff[104];

    if (argc < 2) {
        printf("Syntax: %s <input string>\n", argv[0]);
        exit(0);
    }
    strcpy((char *) &buff, argv[1]);
    return 0;
}
