#include <stdio.h>
#include <string.h>

void concatenate(char **list, int num, char *concatenated)
{
    for (int i = 0; i < num; i++)
    {
        // BUG 1: Incrementing the wrong pointer
        size_t len = strlen(*(list + i));
        strncpy(concatenated, *(list + i), len);
        concatenated = concatenated + len;
    }
}

int main()
{
    char *list[512];
    char buffer[1024];
    // BUG 2: Buffer not initialized to null characters
    memset(buffer, 0, sizeof(char) * 1024);

    char *str_1 = "a";
    char *str_2 = "b";
    char *str_3 = "c";

    list[0] = str_1;
    list[1] = str_2;
    list[2] = str_3;

    concatenate(list, 3, buffer);
    printf("String 1: %s\n", str_1);
    printf("String 2: %s\n", str_2);
    printf("String 3: %s\n", str_3);
    printf("%s\n", buffer);
    
    return 0;
}