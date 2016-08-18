#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <mqueue.h>

#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sim.h>


extern int ingress_port;
extern char server_ip[];
extern int server_port;
int setup_udp_server(int port);


void *uac_loop(void *arg) {

    mqd_t rdq;
    struct mq_attr attr;
    char *uac_buf;
    int uac_buf_len;
    int sockfd, bytes;
    sim_msg_t *msg;
    struct sockaddr_in proxyaddr;

    printf("UAC client thread running ...\n");

    rdq = mq_open(UAC_Q_NAME, O_RDONLY);
    if (rdq == -1) {
        fprintf(stderr, "UAC: unable to open the uac message queue\n");
        return NULL;
    }

    if (mq_getattr(rdq, &attr)) {
        perror("mq_getattr ");
        fprintf(stderr, "UAC: unable to get MQ attributes\n");
        attr.mq_msgsize = 1500;
    }

    printf ("UAC mq_msgsize: %ld\n", attr.mq_msgsize);
    printf ("UAC mq_maxmsg: %ld\n", attr.mq_maxmsg);

    uac_buf_len = attr.mq_msgsize;

    uac_buf = (char *) malloc (uac_buf_len);
    if (uac_buf == NULL) {
        fprintf(stderr, "memory allocation failed\n");
        return NULL;
    }

    sockfd = setup_udp_server(ingress_port);
    if (sockfd == 0) {
        fprintf(stderr, "Error when setting up UAC server, bailing out...\n");
        return NULL;
    }

    // setup proxy address 
    bzero((char *)&proxyaddr, sizeof(proxyaddr));
    proxyaddr.sin_family = AF_INET;
    proxyaddr.sin_addr.s_addr = inet_addr(server_ip);
    proxyaddr.sin_port = htons(server_port);

    while (1) {

        memset(uac_buf, 0, uac_buf_len);

        if (mq_receive(rdq, uac_buf, uac_buf_len, NULL) == -1) {
            perror("UAC: mq_receive");
            return NULL;
        }

        msg = (sim_msg_t *)uac_buf;

        if (msg->op == PCAP_SEND) {

            printf("UAC: Send packet out\n");

            bytes = sendto(sockfd, msg->data, msg->size, 0, 
                    (struct sockaddr *) &proxyaddr, sizeof(proxyaddr));
            if (bytes < 0) {
                perror("sendto ");
                fprintf(stderr, "Error sending message to proxy\n");
            }
        } else { 
            printf("UAC: Wait for packet from proxy\n");
        }

        /*
        if (uac_buf_len > 0) {
            const u_char *temp_pointer = msg->data;
            int byte_count = 0;
            while (byte_count++ < msg->size) {
                printf("%c", *temp_pointer);
                temp_pointer++;
            }
            printf("\n");
        }
        */
    }
    
    return NULL;
}


