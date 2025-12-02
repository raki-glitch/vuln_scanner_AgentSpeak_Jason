#include <stdio.h>
#include <string.h>

void unsafe_copy(char *input) {
    char buffer[10];
    strcpy(buffer, input); 
    printf("%s\n", buffer);
}

int main() {
    char data[50];
    gets(data);
    unsafe_copy(data);
    return 0;
}
