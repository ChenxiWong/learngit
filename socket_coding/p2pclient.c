// Last Update:2017-05-14 12:41:15
/**
 * @file p2pserver.c
 * @brief 
 * @author wangchenxi
 * @version 0.1.00
 * @date 2017-05-14
 */
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#define ERR_EXIT(m) \
    do \
    { \
        perror(m); \
        exit(EXIT_FAILURE); \
    } while(0)

void handler(int sig)
{
    printf("signle is %d \n", sig);
    exit(EXIT_SUCCESS);
}

int main(int argc, char* argv[])
{
    int sock;
    if((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        ERR_EXIT("socket");
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(5188);
    /*servaddr.sin_addr.s_addr = htonl(INADDR_ANY); */
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    /*
     *inet_aton("127.0.0.1, &servaddr.sin_addr);
     */
    if(connect(sock, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0)
        ERR_EXIT("connect");
    pid_t pid;
    pid = fork();
    if(pid == -1)
        ERR_EXIT("fork");

    if(pid == 0)
    {
        signal(SIGUSR1, handler);
        char sendbuff[1024];
        memset(sendbuff, 0, 1024);
        while(fgets(sendbuff, sizeof(sendbuff), stdin) != NULL)
        {
            write(sock, sendbuff, strlen(sendbuff));
            memset(sendbuff, 0, 1024);
        }
        exit(EXIT_SUCCESS);
    }
    else
    {
        char recvbuf[1024];
        memset(recvbuf, 0, 1024);
        while(1)
        {
            int ret = read(sock, recvbuf, sizeof(recvbuf));
            if (ret == -1)
                ERR_EXIT("read");
            else if (ret == 0)
            {
                printf("peer close\n");
                break;
            }
            fputs(recvbuf, stdout);
        }
        printf("parent close\n");
        kill(pid, SIGUSR1);
        exit(EXIT_SUCCESS);
    }
    return 0;
}



