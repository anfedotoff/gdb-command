#include <stdlib.h>
#include <stdio.h>
#include <string.h>


int main(int argc, char ** argv) {
    char buff[100];

    if (argc < 2) {
        __printf_chk(1, "Syntax: %s <input string>\n", argv[0]);
        exit(0);
    }
    __strcpy_chk((char *) &buff, argv[1], sizeof(buff));
    return 0;
}
