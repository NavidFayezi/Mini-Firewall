#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */
#include <string.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

struct ip_address{
    uint8_t octets [4];
};

uint16_t *current_j;
uint16_t *input_j;
uint16_t *input_port_number;
char *pattern;
struct ip_address *input_ip;



uint8_t get_ip_header_length(unsigned char data){
    uint8_t hl = data & 0x0f;
    return hl << 2;    // hl is the number of 32 bit words(4 bytes)
}

char** ip_string_preprocess(char * ip_str){
    int i, j, len, pivot, octet_size;
    len = strlen(ip_str);
    char ** octets = malloc(sizeof(char*) * 4);
    pivot = 0;
    j = 0;
    for (i = 0; i < len; i++){
        if(ip_str[i] == '.'){
            octet_size = i - pivot;
            octets[j] = malloc(sizeof(char) * (octet_size + 1));
            strncpy(octets[j], &ip_str[pivot], octet_size);
            pivot = i + 1;
            j++;
        }
    }
    // last octet
    octet_size = len - pivot;
    octets[j] = malloc(sizeof(char) * (octet_size + 1));
    strncpy(octets[j], &ip_str[pivot], octet_size);

    return octets;
}

uint16_t str_to_uint(char* str){
    int j;
    int len = strlen(str);
    uint16_t temp = 0;

    for(j = 0; j < len; j++){
        temp = (temp * 10) + (str[j] - '0');
    }
    return temp;
}

struct ip_address* ip_string_to_struct(char ** ip_str){

    int i;

    struct ip_address *ip = malloc(sizeof(struct ip_address));

    for (i = 0; i < 4; i++){
        ip->octets[i] = str_to_uint(ip_str[i]);
    }

    return ip;
}

int appearance_count_in_payload(char* payload, char* pattern, int payload_len, int pattern_len){
    int i, j, flag, counter;
    counter = 0;

    for (i = 0; i <= payload_len - pattern_len; i++){
        if(payload[i] == pattern[0]){
            flag = 1;
            for(j = 1; j < pattern_len; j++){
                if(payload[i + j] != pattern[j]){
                    flag = 0;
                    break;
                }
            }
            if(flag == 1){
                counter++;
            }
        }
    }
    return counter;

}

void print_bin(unsigned char value)
{
    int i;
    for (i = 0; i < 8; i++) {
        printf("%d", !!((value << i) & 0x80));
    }
}

int match_rule(uint16_t *in_port, uint16_t packet_port,
               struct ip_address *input_ip, struct ip_address *packet_ip, char *in_pattern, char *udp_payload)
{


}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    char *data;
    char *udp_payload;
    int i;
    uint8_t header_len;
    uint16_t src_port;
    uint16_t udp_len, udp_payload_len;
    struct ip_address ip;

    ph = nfq_get_msg_packet_hdr(tb);

    /*if (ph) {
          id = ntohl(ph->packet_id);
          printf("hw_protocol=0x%04x hook=%u id=%u ",
                ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
          int i, hlen = ntohs(hwph->hw_addrlen);

          printf("hw_src_addr=");
          for (i = 0; i < hlen-1; i++)
                printf("%02x:", hwph->hw_addr[i]);
          printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
          printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
          printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
          printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
          printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
          printf("physoutdev=%u ", ifi);

    */



    ret = nfq_get_payload(tb, &data);
    //if (ret >= 0)
    //printf("payload_len=%d ", ret);
    // data + 12 -> first octet of source ip address
    ip.octets[0] = data[12];
    ip.octets[1] = data[13];
    ip.octets[2] = data[14];
    ip.octets[3] = data[15];

    // IP header length.
    header_len = get_ip_header_length(data[0]);

    // data + (header_len) -> begining of the UDP segment(first two bytes are src port)
    src_port = ntohs(*((uint16_t*)(data + header_len * sizeof(char))));

    // data + (header_len) + 4 -> size of the UDP segment
    udp_len = ntohs(*((uint16_t*)(data + ((header_len + 4) * sizeof(char)))));

    // the size of a udp header is 8 bytes.
    udp_payload_len = udp_len - 8;

    // data + (header_len) + 8 -> first byte of UPD payload
    udp_payload = data + ((header_len + 8) * sizeof(char));


    printf("\nIP: %u.%u.%u.%u\nSource Port: %u\nudplen: %u\n", ip.octets[0], ip.octets[1], ip.octets[2], ip.octets[3], src_port, udp_len);
    fputc('\n', stdout);

    return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
    //printf("entering callback\n");
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

void get_input(char *arg1, char *arg2, char *arg3, char *arg4){
    char *input_ip_string;
    char *port_string = arg2;
    char *j_string = arg3;
    pattern = arg4;
    input_ip_string = arg1;

    input_port_number = malloc(sizeof(uint16_t));
    current_j = malloc(sizeof(uint16_t));

    input_j = malloc(sizeof(uint16_t));  // maximum number of iteration, given by user
    input_ip = malloc(sizeof(struct ip_address));
    *input_j = str_to_uint(j_string);    // number of iterations

    *current_j = 0;
    *input_port_number = str_to_uint(port_string);
    input_ip = ip_string_to_struct(ip_string_preprocess(input_ip_string));
    return;
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
    // command line arguments

    get_input(argv[1], argv[2], argv[3], argv[4]);
    system("./add_rule.sh");
    printf("opening library handle\n");
    /* This function obtains a netfilter queue connection handle.
       When you are finished with the handle returned by this function,
       you should destroy it by calling nfq_close(). A new netlink connection
       is obtained internally and associated with the queue connection handle returned.
       Returns a pointer to a new queue handle or NULL on failure.
    */
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    /* Bind a nfqueue handler to a given protocol family.
       First parameter: Netfilter queue connection handle
       obtained via call to nfq_open().
       Second parameter: Protocol family. IPv4
    */
    /* obsolete
    if (nfq_unbind_pf(h, AF_INET) < 0) {
          fprintf(stderr, "error during nfq_unbind_pf()\n");
          exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
          fprintf(stderr, "error during nfq_bind_pf()\n");
          exit(1);
    }*/

    printf("binding this socket to queue '0'\n");
    /* create a new queue handle and return it.
       Parameters: Netfilter queue connection handle obtained
       via call tonfq_open().
       The number of the queue to bind to.
       Callback function to call for each queued packet.
       Custom data to pass to the callback function.
       Returns a nfq_q_handle pointing to the newly created queue.

    */
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }
    /* set the amount of packet data that nfqueue copies to userspace
       Parameters:
       Netfilter queue handle obtained by call to nfq_create_queue().
       the part of the packet that we are interested in
       size of the packet that we want to get
       Sets the amount of data to be copied to userspace for each packet queued to the given queue.
       NFQNL_COPY_NONE - noop, do not use it
       NFQNL_COPY_META - copy only packet metadata
       NFQNL_COPY_PACKET - copy entire packet
       Returns:
       -1 on error; >=0 otherwise.
    */
    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }
    /* get the file descriptor associated with the nfqueue handler
       Parameters:
       Netfilter queue connection handle obtained via call to nfq_open().
       Returns:
       a file descriptor for the netlink connection associated with
       the given queue connection handle. The file descriptor can
       then be used for receiving the queued packets for processing.
       This function returns a file descriptor that can be used for
       communication over the netlink connection associated with the given queue connection handl
    */
    fd = nfq_fd(h);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        //printf("pkt received\n");
        /* handle a packet received from the nfqueue subsystem
           Parameters:
           Netfilter queue connection handle obtained via call to nfq_open()
           data to pass to the callback
           length of packet data in buffer
           Triggers an associated callback for the given packet received from the queue.
           Packets can be read from the queue using nfq_fd() and recv(). See example code for nfq_fd().
           Returns:
           0 on success, non-zero on failure
        */
        nfq_handle_packet(h, buf, rv);
        /*if (*j_iter >= *j_input)
              break;*/

    }

    printf("unbinding from queue 0\n");
    /* destroy a queue handle
       Parameters:
       queue handle that we want to destroy created via nfq_create_queue
       Removes the binding for the specified queue handle.
       This call also unbind from the nfqueue handler, so you don't have to call nfq_unbind_pf
    */
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
       * it detaches other programs/sockets from AF_INET, too ! */
      printf("unbinding from AF_INET\n");
      nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);     // close nfque handler and free its associated resources.
    // return zero on success, non-zero on failure.
    system("./delete_rule.sh");
    //printf("%d\n", *j_iter);
    exit(0);
}
