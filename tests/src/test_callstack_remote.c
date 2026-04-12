#include <signal.h>

void third(int val) {
    raise(20);
}

void second(int val) {
    third(val);
}
void first(int val) {
    second(val);
}

int main(int argc, char ** argv) {
    first(argc);
    return 0;
}