#include <stdio.h>
#include <stdlib.h>
void length(char *str);
int main() {
    length("A12345");
    return 0;
}
void length(char *str) {
    printf("Length of the string is: %d\n", strlen(str));
}