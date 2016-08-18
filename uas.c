#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <mqueue.h>

#include <sim.h>


extern int egress_port;
int setup_udp_server(int port);



void *uas_loop(void *arg) {

    mqd_t rdq;
    struct mq_attr attr;
    char *uas_buf;
    int uas_buf_len;
    int sockfd;
    sim_msg_t *msg;

    printf("UAS client thread running ...\n");

    rdq = mq_open(UAS_Q_NAME, O_RDONLY);
    if (rdq == -1) {
        fprintf(stderr, "UAS: unable to open the uac message queue\n");
        return NULL;
    }

    if (mq_getattr(rdq, &attr)) {
        perror("mq_getattr ");
        fprintf(stderr, "UAS: unable to get MQ attributes\n");
        return NULL;
    }

    uas_buf_len = attr.mq_msgsize;

    uas_buf = (char *) malloc (uas_buf_len);
    if (uas_buf == NULL) {
        fprintf(stderr, "memory allocation failed\n");
        return NULL;
    }

    sockfd = setup_udp_server(egress_port);
    if (sockfd == 0) {
        fprintf(stderr, "Error when setting up UAS server, bailing out...\n");
        return NULL;
    }

    while (1) {

        memset(uas_buf, 0, uas_buf_len);

        if (mq_receive(rdq, uas_buf, uas_buf_len, NULL) == -1) { 
            perror("UAS: mq_receive");
            return NULL;
        }

        msg = (sim_msg_t *)uas_buf;

        if (msg->op == PCAP_SEND) {
            printf("UAS: Send packet out\n");
        } else { 
            printf("UAS: Wait for packet from proxy\n");
        }
    }
 

    return NULL;
}
