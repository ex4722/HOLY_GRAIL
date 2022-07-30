#include <stdio.h>

int main (int argc, char *argv[])
{
    setvbuf(stdout, 0, 0, 0);
    puts("HELLO");
    return 0;

}
