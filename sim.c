#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <pthread.h>

#include <unistd.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <mqueue.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sim.h>


void *uac_loop(void *arg);
void *uas_loop(void *arg);


struct UDP_header {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	u_short	uh_ulen;		/* datagram length */
	u_short	uh_sum;			/* datagram checksum */
};


char server_ip[] = "74.117.36.136";
int server_port = 5060;
char pcap_uac_ip[] = "74.117.36.132";
int egress_port = 5066;
int ingress_port = 5055;
static mqd_t uac_q, uas_q;


void sim_packet_handler(
    u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    static int count = 0, server_ip_len, src_ip_len, dst_ip_len;
    unsigned char src_ip[16] = {0}, dst_ip[16] = {0};
    struct in_addr pkt_src, pkt_dst;

    count++;
    printf("Packet count: %d\n", count);

    /* First, lets make sure we have an IP packet */
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Not an IP packet. Skipping...\n\n");
        return;
    }

    /* The total packet length, including all headers
       and the data payload is stored in
       header->len and header->caplen. Caplen is
       the amount actually available, and len is the
       total packet length even if it is larger
       than what we currently have captured. */
    //printf("Total packet available: %d bytes\n", header->caplen);
    //printf("Expected packet size: %d bytes\n", header->len);

    /* Pointers to start point of various headers */
    const u_char *ip_header;
    struct UDP_header *udp_header;
    const u_char *payload;

    /* Header lengths in bytes */
    int ethernet_header_length = 14; /* Doesn't change */
    int ip_header_length;
    int udp_header_length;
    int payload_length;

    /* Find start of IP header */
    ip_header = packet + ethernet_header_length;
    /* The second-half of the first byte in ip_header
       contains the IP header length (IHL). */
    ip_header_length = ((*ip_header) & 0x0F);
    /* The IHL is number of 32-bit segments. Multiply
       by four to get a byte count for pointer arithmetic */
    ip_header_length = ip_header_length * 4;
    //printf("IP header length (IHL) in bytes: %d\n", ip_header_length);


    memcpy((void *)&pkt_src, (ip_header+12), 4);
    memcpy((void *)&pkt_dst, (ip_header+16), 4);

    strncpy((char *)src_ip, inet_ntoa(pkt_src), 15);
    strncpy((char *)dst_ip, inet_ntoa(pkt_dst), 15);

    printf("++++++++++++++++++++++++++++\n");
    printf("Count: %d\n", count);
    printf("PKT source: %s\n", src_ip);
    printf("PKT destination: %s\n", dst_ip);

    /* Now that we know where the IP header is, we can 
       inspect the IP header for a protocol number to 
       make sure it is TCP before going any further. 
       Protocol is always the 10th byte of the IP header */
    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_UDP) {
        printf("Not a UDP packet. Skipping...\n\n");
        return;
    }

    /* Add the ethernet and ip header length to the start of the packet
       to find the beginning of the UDP header */
    udp_header = (struct UDP_header *)(packet + ethernet_header_length + ip_header_length);
    /* UDP header length is stored in the first half 
       of the 12th byte in the UDP header. Because we only want
       the value of the top half of the byte, we have to shift it
       down to the bottom half otherwise it is using the most 
       significant bits instead of the least significant bits */
    udp_header_length = 8;
    //payload_length = ntohs(udp_header->uh_ulen);
    /* The TCP header length stored in those 4 bits represents
       how many 32-bit words there are in the header, just like
       the IP header length. We multiply by four again to get a
       byte count. */
    //udp_header_length = udp_header_length * 4;
    //printf("UDP header length in bytes: %d\n", udp_header_length);

    /* Add up all the header sizes to find the payload offset */
    int total_headers_size = ethernet_header_length+ip_header_length+udp_header_length;
    //printf("Size of all headers combined: %d bytes\n", total_headers_size);
    payload_length = header->caplen -
        (ethernet_header_length + ip_header_length + udp_header_length);
    //printf("Payload size: %d bytes\n", payload_length);
    payload = packet + total_headers_size;
    //printf("Memory address where payload begins: %p\n\n", payload);


    server_ip_len = strlen(server_ip);
    src_ip_len = strlen(src_ip);
    dst_ip_len = strlen(dst_ip);

    sim_msg_t *s = (sim_msg_t *) malloc (sizeof(sim_msg_t) + payload_length);
    if (s == NULL) {
        perror("malloc ");
        fprintf(stderr, "memory allocation failure\n");
        return;
    }

    if ((!strncmp(server_ip, dst_ip, server_ip_len)) && 
            (!strncmp(pcap_uac_ip, src_ip, src_ip_len))) {

        s->op = PCAP_SEND;
        s->size = payload_length;
        memcpy(s->data, payload, payload_length);

        /* queue it to be sent via uac */
        if (mq_send(uac_q, (char *)s, (sizeof(sim_msg_t)+payload_length), 0) == -1) {
            printf("Unable to send msg over UAC queue\n");
            perror("mq_send ");
        }
        printf("Queued to UAC to send out : length %d\n", payload_length);
    } else if ((!strncmp(server_ip, src_ip, server_ip_len)) &&
            (!strncmp(pcap_uac_ip, dst_ip, dst_ip_len))) {

        s->op = PCAP_WAIT;
        s->size = payload_length;
        memcpy(s->data, payload, payload_length);

        /* queue it to be sent via uac */
        if (mq_send(uac_q, (char *)s, (sizeof(sim_msg_t)+payload_length), 0) == -1) {
            printf("Unable to send msg over UAC queue\n");
            perror("mq_send ");
        }
        printf("Queued to UAC to WAIT : length %d\n", payload_length);

    } else if ((!strncmp(server_ip, src_ip, server_ip_len)) && 
            (server_ip_len == src_ip_len)) {

        s->op = PCAP_WAIT;
        s->size = payload_length;
        memcpy(s->data, payload, payload_length);

        /* queue it for uas processing */
        if (mq_send(uas_q, (char *)s, (sizeof(sim_msg_t)+payload_length), 0) == -1) {
            printf("Unable to send msg over UAS queue\n");
            perror("mq_send ");
        }
        printf("Queued to UAS for WAIT : length %d\n", payload_length);
    } else if ((!strncmp(server_ip, dst_ip, server_ip_len)) &&
           (server_ip_len == dst_ip_len)) {

        s->op = PCAP_SEND;
        s->size = payload_length;
        memcpy(s->data, payload, payload_length);

        /* queue it for uas processing */
        if (mq_send(uas_q, (char *)s, (sizeof(sim_msg_t)+payload_length), 0) == -1) {
            printf("Unable to send msg over UAS queue\n");
            perror("mq_send ");
        }
        printf("Queued to UAS to SEND : length %d\n", payload_length);

    } else {
        printf("Dropping unknown packet\n");
    }

    sleep(3);

    /* Print payload in ASCII */
    /*
    if (payload_length > 0) {
        const u_char *temp_pointer = payload;
        int byte_count = 0;
        while (byte_count++ < payload_length) {
            printf("%c", *temp_pointer);
            temp_pointer++;
        }
        printf("\n");
    }
    */

    return;
}




int main(int argc, char **argv) {    

    char *device = NULL;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    pthread_t uac_t, uas_t;


    if (argc < 2) {
        printf("uasge: ./sim pcap_file\n");
        //printf("uasge: ./sim server egress_port ingress_port pcap\n");
        return 1;
    }

    device = pcap_lookupdev(error_buffer);
    if (device == NULL) {
        printf("Error finding device: %s\n", error_buffer);
        return 1;
    }

    handle = pcap_open_offline(argv[1], error_buffer);
    if (handle == NULL) {
        printf("Error opening the given pcap file: %s\n",error_buffer);
        return 1;
    }

    mq_unlink(UAC_Q_NAME);
    mq_unlink(UAS_Q_NAME);

    // create the queues before spawning the threads
    uac_q = mq_open(UAC_Q_NAME, O_CREAT | O_EXCL | O_WRONLY, Q_PERMISSIONS, NULL);
    if (uac_q == -1) {
        fprintf(stderr, "creation of UAC message queue failed\n");
        return 1;
    }

    uas_q = mq_open(UAS_Q_NAME, O_CREAT | O_EXCL | O_WRONLY, Q_PERMISSIONS, NULL);
    if (uas_q == -1) {
        fprintf(stderr, "creation of UAS message queue failed\n");
        return 1;
    }

    if (pthread_create(&uac_t, NULL, uac_loop, NULL)) {
        fprintf(stderr, "Error creating uac thread\n");
        return 1;
    }

    if (pthread_create(&uas_t, NULL, uas_loop, NULL)) {
        fprintf(stderr, "Error creating uas thread\n");
        return 1;
    }

    printf("created uac and uas threads ...\n");

    pcap_loop(handle, 0, sim_packet_handler, NULL);

    pcap_close(handle);

    return 0;
}

