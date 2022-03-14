#include <iostream>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace std;

#define SERVERPORT 5555

void clientMode();
void serverMode();
void secretChat(int clientSocket, char *strIpAddr, char *key);

int main(){
    bool input = false;
    while(!input){
        printf("Client or Server?\r\n");
        char mode;
        cin >> mode;
        if (mode == 'c' || mode == 'C')
        {
            //Client mode
            input = true;
            clientMode();

        }
        else if (mode == 's' || mode == 'S')
        {
            //Server mode
            input = true;
            serverMode();
        }
        else
        {
            printf("Wrong input!\n");
        }
    }
    return 0;
}

void clientMode(){
    char strIpAddr[16];
    printf("Please input the server address:\r\n");
    cin >> strIpAddr;
    int clientSocket;
    struct sockaddr_in serverAddr;
    //创建socket
    if ((clientSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        printf("Create socket fail");
        return;
    }
    //初始化serverAddr
    bzero(&serverAddr, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(strIpAddr);
    serverAddr.sin_port = htons(SERVERPORT);
    //connect服务器
    if (connect(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) != 0)
    {
        printf("Connect socket fail");
        return;
    }
    printf("Connect Success!\nBegin to chat...\n");
    secretChat(clientSocket, strIpAddr, "benbenmi");
    return;
}

void serverMode(){
    int serverSocket, clientSocket;
    struct sockaddr_in serverAddr, clientAddr;
    //创建socket
    if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        printf("Create socket fail");
        return;
    }
    //初始化serverAddr
    bzero(&serverAddr, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(SERVERPORT);
    //绑定socket
    if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(struct sockaddr)) == -1)
    {
        printf("Bind socket fail");
        return;
    }
    //listen socket
    if (listen(serverSocket, 5) == -1)
    {
        printf("listen socket fail");
        return;
    }
    printf("Listening...\n");
    socklen_t socklen = sizeof(struct sockaddr);
    //accept socket
    if ((clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddr, &socklen)) == -1)
    {
        printf("accept socket fail");
        return;
    }
    close(serverSocket);
    printf("server: got connectoin from %s, port %d, socket %d\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port), clientSocket);
    secretChat(clientSocket, inet_ntoa(clientAddr.sin_addr), "benbenmi");
    close(clientSocket);
    return;
}

void secretChat(int clientSocket, char *strIpAddr, char *key){
    printf("secretChat\n");
    return;
}