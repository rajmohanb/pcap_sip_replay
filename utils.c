#include <stdio.h>
#include <strings.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


int setup_udp_server(int port) {

    int sockfd;
    struct sockaddr_in localaddr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket ");
        fprintf(stderr, "socket creation failed\n");
        return 0;
    }

    bzero((char *) &localaddr, sizeof(localaddr));
    localaddr.sin_family = AF_INET;
    localaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    localaddr.sin_port = htons((unsigned short)port);     

    if (bind(sockfd, (struct sockaddr *) &localaddr, sizeof(localaddr)) < 0) {
        perror("bind ");
        fprintf(stderr, "error binding to local addr on port %d\n", port);
        return 0;
    }

    return sockfd;
}
