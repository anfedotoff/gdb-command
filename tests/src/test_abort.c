#include <stdlib.h>
#include <stdio.h>


int main(int argc, char ** argv) {
    if (argc < 2) {
        printf("Syntax: %s <input string>\n", argv[0]);
        exit(0);
    }
    if ('A' == argv[1][0]) {
        abort();
    }
    return 0;
}
