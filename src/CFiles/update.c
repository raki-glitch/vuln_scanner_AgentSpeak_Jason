#include <stdio.h>
#include <string.h>

void unsafe_copy(char *input) {
    char buffer[10];
    strcpy(buffer, input); 
    printf("%s\n", buffer);
}

// void safe_copy(char *input) {
//     char buffer[100];
//     strncpy(buffer, input, 99);
//     buffer[99] = '\0';
//     printf("%s\n", buffer);
// }

int main() {
    char data[50];
    gets(data);
    unsafe_copy(data);
    return 0;
}
