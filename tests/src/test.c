

/* test.c  for ReturnAv*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main(int argc, char* argv[])

{

    char buf[32];
    char c;
    int i = 0;
    while ((c = getchar()) != '\n' && c != EOF) {
        buf[i++] = c;
    }

    return 0;
}
