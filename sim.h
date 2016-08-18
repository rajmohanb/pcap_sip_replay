
#ifndef SIM__H
#define SIM__H

#ifdef __cplusplus
extern "C" {
#endif


#define UAC_Q_NAME  "/uac_q"
#define UAS_Q_NAME  "/uas_q"
#define Q_PERMISSIONS   0660

typedef enum pcap_op {
    PCAP_SEND = 1,
    PCAP_WAIT = 2,
} pcap_op_t;

typedef struct uac_msg {
    pcap_op_t op;
    int size;
    char data[];
} sim_msg_t;

#ifdef __cplusplus
}
#endif

#endif

