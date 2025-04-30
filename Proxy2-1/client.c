// =================================================================
// File Name    : client.c
// Date         : 2025/05/01
// OS           : Ubuntu 22.04 LTS 64bits
// Author       : Choe Hyeon Jin
// Student ID   : 2023202070
// -----------------------------------------------------------------
// Title        : System Programming proxy Assignment #2-1
// Description  : A program that sends URL to server 
//                      and prints HIT or MISS result received from server
// =================================================================

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>

#define PORT 1234
#define BUF_SIZE 1024

// =================================================================
// Function     : main
// -----------------------------------------------------------------
// Input        : -
// Output       : int - 0 success
// Purpose      : Getting URL from user, 
//                       sending it to server, printing hit/miss result
// =================================================================

int main() {
    int sd; // server socket descriptor
    struct sockaddr_in server; // socket address struct
    char url[BUF_SIZE];
    char result[BUF_SIZE];

    sd = socket(AF_INET, SOCK_STREAM, 0); // create socket

    // server's socket address initialization
    memset((char*)& server, '\0', sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    server.sin_addr.s_addr = inet_addr("127.0.0.1");

    // connect to server
    connect(sd, (struct sockaddr*)&server, sizeof(server));

    // after server's accept
    while (1) {
        printf("input url > ");
        scanf("%s", url);

        write(sd, url, strlen(url) + 1);  // send(write) input url to server

        // if input "bye"
        if (strcmp(url, "bye") == 0) {
            break;
        }
        // read(receive) and print HIT/MISS result from server
        read(sd, result, BUF_SIZE);
        printf("%s\n", result);
    }

    close(sd);
    return 0;
}
