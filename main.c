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

struct packet_data
{
    int recurrance_number;
    char *udp_payload;
    uint16_t udp_payload_len;
};

// there was not any clear documention for "cb" function,
// that is why I had to declare these global variables instead of passing them to "cb".
uint16_t *current_j;
uint16_t *input_j;
uint16_t *input_port_number;
char *pattern;
struct ip_address *input_ip;
struct packet_data **matched_packets;


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
        free(ip_str[i]);
    }
    free(ip_str);
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

int match_rules(uint16_t in_port, uint16_t packet_port,
                struct ip_address *input_ip, struct ip_address *packet_ip, char *in_pattern, char *udp_payload, int payload_len)
{
    if(packet_port == in_port && packet_ip->octets[0] == input_ip->octets[0] && packet_ip->octets[1] == input_ip->octets[1]
       && packet_ip->octets[2] == input_ip->octets[2] && packet_ip->octets[3] == input_ip->octets[3]){

        return appearance_count_in_payload(udp_payload, in_pattern, payload_len, strlen(in_pattern));
    }
    else{
        return 0;
    }

}

void save_packet_data(int appearance_no, char *upd_payload, uint16_t upd_payload_len){
    if(*current_j < *input_j){
        int i;
        struct packet_data *pckt = malloc(sizeof(struct packet_data));
        pckt->recurrance_number = appearance_no;
        pckt->udp_payload_len = upd_payload_len;
        pckt->udp_payload = malloc(sizeof(char) * upd_payload_len);
        // deep copy
        for (i = 0; i < (int)upd_payload_len; i++){
            pckt->udp_payload[i] = upd_payload[i];
        }
        //matched_packets [(*current_j)] = malloc(sizeof(struct packet_data));
        matched_packets [(*current_j)] = pckt;
        (*current_j)++;
    }
}

void write_to_file(){
    int i, j;
    FILE *output_file = fopen("out.txt", "w");

    for(i = 0; i < *input_j; i++){
        fprintf(output_file, "Payload: ");
        for(j = 0; j < matched_packets[i]->udp_payload_len; j++){
            fprintf(output_file, "%c", matched_packets[i]->udp_payload[j]);
        }
        fprintf(output_file, "\nAppearances: %d\n", matched_packets[i]->recurrance_number);

    }
    fclose(output_file);
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
    int matched; // if packet matches the rules, it holdes the number of appearance in the payload, otherwise = 0.
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


    ret = nfq_get_payload(tb, &data);

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

    matched = match_rules(*input_port_number, src_port, input_ip, &ip, pattern, udp_payload, udp_payload_len);
    if (matched){
        /*printf("Payload: ");
        for(i = 0; i < udp_payload_len; i++){
            printf("%c", udp_payload[i]);
        }
        printf("\nAppearances: %d\n", matched);*/
        save_packet_data(matched, udp_payload, udp_payload_len);
    }
    //printf("\nIP: %u.%u.%u.%u\nSource Port: %u\nudplen: %u\n", ip.octets[0], ip.octets[1], ip.octets[2], ip.octets[3], src_port, udp_len);
    //fputc('\n', stdout);

    return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
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
    //input_ip = malloc(sizeof(struct ip_address));
    *input_j = str_to_uint(j_string);    // number of iterations

    matched_packets = malloc(sizeof(struct packet_data*) * (*input_j));

    *current_j = 0;
    *input_port_number = str_to_uint(port_string);
    input_ip = ip_string_to_struct(ip_string_preprocess(input_ip_string));
    return;
}

void free_heap(){
    int i;

    for(i = 0; i < *input_j; i++){
        free(matched_packets[i]->udp_payload);
        free(matched_packets[i]);
    }

    free(input_port_number);
    free(input_j);
    free(current_j);
    free(input_ip);
    free(matched_packets);

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

    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");

    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {

        nfq_handle_packet(h, buf, rv);
        if(*current_j >= *input_j)
            break;
    }

    printf("unbinding from queue 0\n");

    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
       * it detaches other programs/sockets from AF_INET, too ! */
      printf("unbinding from AF_INET\n");
      nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);
    write_to_file();
    system("./delete_rule.sh");
    free_heap();
    exit(0);
}
