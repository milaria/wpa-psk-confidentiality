//
//  main.c
//  NetSec
//
//  Created by Ilaria Martinelli on 19/11/12.
//  Copyright (c) 2012 Ilaria Martinelli. All rights reserved.
//


//Confidentiality in WPA-personal (802.11 networks)
//
//In this case the student will design and implement a mechanism that violates confidentiality of WiFi networks based on WPA-PSK (AKA "WPA-Personal").
//The system will assume that the attacker knows the PSK: by intercepting authentication messages exchanged by legitimate clients and APs using the same PSK, the system will derive the same ephemeral keys installed by other clients, and show that it is indeed possible to decrypt the entire session between other clients and the APs.


#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <openssl/hmac.h>

#include "util_functions.h"
#include "enc_functions.h"

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518
#define VERBOSE 0

typedef enum{
    MESSAGE_1,
    MESSAGE_2,
    MESSAGE_3,
    MESSAGE_4
}eapolKeyType;

extern Phandshake_data sta_data[MAX_NUM_STA];
int num_sta=0;
extern u_char * PSK;

void got_packet_radiotap(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void open_ieee_packet(const u_char *ieee_packet, int * content_len);
void open_llc_packet(const u_char *llc_packet,u_char *address_1,u_char *address_2,u_char *address_3,int current_i);
void open_eapol(const u_char *eapol_packet,u_char *address_1,u_char *address_2,u_char *address_3,int current_i);
void message_1(const u_char *eapol_key,u_char *address_1,u_char *address_2,u_char *address_3,int current_i);
char* address_format(char address_1[6]);
int new_sta(u_char *address_1);
eapolKeyType classify_eapol_key(int key_MIC, int key_ack, int install, int key_type, u_char * Nonce);
int get_index(u_char *sta_address);
void print_exString(u_char * str, int len);



int main(int argc, char **argv){
    char* Passphrase;
    u_char* SSID;
    int SSIDLength;
    PSK = (u_char *) malloc(32);
    
    char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
    pcap_t *handle;				/* packet capture handle */
    char* fname;
    
    //options handling
    int c;
    opterr = 0;
    while ((c = getopt(argc, argv, "s:p:f:")) != -1){
        switch (c) {
            case 's':
                SSID = (u_char *) optarg;
                break;
            case 'p':
                Passphrase = optarg;
                break;
            case 'f':
                fname = optarg;
                break;
            case '?':
                if (isprint (optopt))
                    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                else
                    fprintf (stderr,"Unknown option character `\\x%x'.\n", optopt);
                return(EXIT_FAILURE);
            default:
                abort();
        }
    }
    
    if (fname == NULL || SSID == NULL || Passphrase == NULL) {
        fprintf (stderr, "Missing some information, unable to continue\n");
        printf("Usage is:\n\t ns_project -f <file name> -s <SSID> -p <passphrase>\n");
        return(EXIT_FAILURE);
    }
    
    printf("Reading from file: \"%s\"\n", fname);
    printf("SSID = \"%s\"\n", SSID);
    printf("Passphrase = \"%s\"\n", Passphrase);
    
    SSIDLength = (int)strlen((char *)SSID);
    u_char * output = (u_char *) malloc(40);
    PSK = (u_char *) malloc(32*sizeof(u_char));
    
    PasswordHash(Passphrase, SSID, SSIDLength, output);
    memcpy(PSK, output, 32*sizeof(u_char));
    
#if VERBOSE
    printf("PSK: ");
    print_exString(PSK, 32);
    printf("\n");
#endif
    
    /* open file */
    handle = pcap_open_offline(fname, errbuf);
    
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open file: %s\n",errbuf);
        exit(EXIT_FAILURE);
    }
    printf("Analizing file: %s\n\n",fname);
    
    if((pcap_datalink(handle)) == DLT_IEEE802_11_RADIO)
        pcap_loop(handle, -1, got_packet_radiotap, NULL);
    
    return 0;
}

void got_packet_radiotap(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    static int count = 0;
    count++; //TODO SPOSTARE

#if VERBOSE
    printf("\nPacket number %d, length: %d\n", count, header->len);
#else
    printf("\n[%d] len: %d", count,header->len);
#endif
    
    u_char header_revision = (u_char)packet[0];
    if(header_revision!=(u_char)'\0'){
        printf("Packet not radiotap standard");
        return;
    }
    
    //u_char header_pad = (u_char)packet[1];
    //u_int header_length[2];
    //header_length[0]=(u_int)(u_char)packet[2];
    //header_length[1]=(u_int)(u_char)packet[3];
    int header_length=(u_int)(u_char)packet[2]+(u_int)(u_char)packet[3]*16*16;
    //printf("header_length:%d\n", header_length);
    
    int content_len = header->len - header_length;
    
    u_char * ieee_packet = (u_char *)packet+header_length;
    
    
    //analyzing ieee_packet
    u_char proto_type_subtype = (u_char)ieee_packet[0];
    int protocol_version = (int)((proto_type_subtype & 0x3));
    int type = (int)((proto_type_subtype & 0xC) >> 2);
    
    if(type != 2) return; //not a data type
    
    int qos = (int)(type == 2) & ((proto_type_subtype & 0xF0) >> 7);
    
    if(protocol_version != 0) return; //not standard
    
    u_char flags = (u_char)ieee_packet[1];
    int to_ds = (int)(flags & 0x1);
    int from_ds = (int)((flags & 0x2) >> 1);
    int protected = (int)((flags & 0x40) >> 6);
    //The Protected Frame field is set to 1 only within data frames and within management frames of subtype Authentication.
    
    //printf("flags: %02x\n",flags);
    //printf("protected %d\n",protected);
    
    //Note that:
    //Address 1 always holds the receiver address of the intended receiver (or, in the case of multicast frames, receivers)
    //Address 2 always holds the address of the STA that is transmitting the frame.
    u_char address_1[6];
    memcpy(address_1, ieee_packet+4, 6*sizeof(u_char));
    u_char address_2[6];
    memcpy(address_2, ieee_packet+4+6, 6*sizeof(u_char));
    u_char address_3[6];
    memcpy(address_3, ieee_packet+4+6+6, 6*sizeof(u_char));
    
    u_char * bssid, * stmac;
    
    if (to_ds == 0 && from_ds == 1) {
        stmac = address_1;
        bssid = address_2;
        printf("-from DS-");
        print_exString(stmac, 6);
    }else if (to_ds == 1 && from_ds == 0){
        printf("-to DS-");
        stmac = address_2;
        bssid = address_1;
        print_exString(stmac, 6);
    }else{
        return;
    }
    
    int current_i = get_index(stmac);
    if(current_i == -1){ //new station
        if (num_sta<MAX_NUM_STA) {
            num_sta++;
            current_i = num_sta - 1;
            sta_data[current_i] = (Phandshake_data)malloc(sizeof(Handshake_data));
            memcpy(sta_data[current_i]->supplicant, stmac, 6 * sizeof(u_char));
            sta_data[current_i]->state = 0;
            
            printf("New station %d", current_i);
            print_exString(stmac, 6);
        } else {
            printf("MAX_NUM_STA was reached, new stations will be ignored.\n");
        }
    }
    printf("\n");
    
    int mac_frame_header_length = 0;
    if(!(from_ds & to_ds)) { //there's no Address 4
        if(!qos) {
            mac_frame_header_length=24;//byte
        }
        else{
            mac_frame_header_length=26;//byte
        }
    }//da controllare
    content_len = content_len - mac_frame_header_length;
    
    if(!protected) {
        //Address 1 always holds the receiver address of the intended receiver (or, in the case of multicast frames, receivers)
        //Address 2 always holds the address of the STA that is transmitting the frame.
        
        const u_char * llc_packet = ieee_packet+mac_frame_header_length;
        
        //int individual = (int) ((llc_packet[0] & 0x80) >> 7);
        //int command = (int) ((llc_packet[0] & 0x80) >> 7);
        //For I/G = 0 the address is individual and for I/G=1 it's a group address.
        u_char type[2];
        memcpy(type, llc_packet+6, 2*sizeof(u_char));
        //printf("%02x%02x\n",type[0],type[1]);
        
        if((type[0]==0x88) && (type[1]==0x8e)){//EAPOL!
            //printf("EAPOL");
            int llc_header_length=8;
            open_eapol(llc_packet+llc_header_length,address_1,address_2,address_3, current_i);
            
        } else { //payload not protected
            //TODO write them
            
        }
        
    }
    else{//protected... trying to decrypt
        /*
         The ExtIV bit in the Key ID octet indicates the presence or absence of an extended IV. If the ExtIV bit is 0, only the nonextended IV is transferred. If the ExtIV bit is 1, an extended IV of 4 octets follows the original IV. For TKIP the ExtIV bit shall be set, and the Extended IV field shall be supplied. The ExtIV bit shall be 0 for WEP frames.
         */
        content_len = content_len - 8 - 4;
        
        if (sta_data[current_i]->state == 0) { //key not valid
            printf(" %d Cannot decrypt, key not computed", current_i);
            return;
        }
        
        u_char * TKIP_par = ieee_packet + mac_frame_header_length;
        
        
        u_short IV16 = 256 * TKIP_par[0] + TKIP_par[2]; //TSC1*256 + TSC0
        u_long IV32 = TKIP_par[4] + 256 * (TKIP_par[5] + 256 * (TKIP_par[6] + 256 * TKIP_par[7])); //TSC2 TSC3 TSC4 TSC5
        
        u_short P1K[80];
        u_char RC4KEY[16];
        u_char * TA = address_2;
        
        Phase1(P1K, sta_data[current_i]->PTK+32, TA, IV32); // sta_data[current_i]->PTK+32 = TK
        Phase2(RC4KEY, sta_data[current_i]->PTK+32, P1K, IV16);
        
        u_char *cleartext = rc4(TKIP_par + 8, content_len, RC4KEY, 16);
        
        //check ICV
        u_int crcCLEAR = (u_int)crc32buf(cleartext, content_len - 4); // 12: 4 (CRC) + IV + EXTIV
        u_int ICV = cleartext[content_len - 4]
        + 256 * (cleartext[content_len - 3]
                 + 256 * (cleartext[content_len - 2]
                          + 256 * cleartext[content_len - 1]));
        if(crcCLEAR!=ICV){
            printf("ICV FAILURE\n");
            free(cleartext);
            return;
        }
#if DEBUG
        else{
            printf("## ICV OK\n");
        }
#endif
        
        //check MIC
        u_char mic[8];
        u_char src_addr[6], dest_addr[6];
        
        /*
         A STA shall use bits 128–191 of the temporal key as the Michael key for MSDUs
         from the Authenticator’s STA to the Supplicant’s STA.
         
         A STA shall use bits 192–255 of the temporal key as the Michael key for MSDUs
         from the Supplicant’s STA to the Authenticator’s STA.
         */
        int offset2mic_key;
        
        if(to_ds == 1 && from_ds == 0){
            memcpy(src_addr, address_2, 6);
            memcpy(dest_addr, address_3, 6);
            offset2mic_key = 32 + 24;
        } else if(to_ds == 0 && from_ds == 1){
            memcpy(src_addr, address_3, 6);
            memcpy(dest_addr, address_1, 6);
            offset2mic_key = 32 + 16;
        } else {
            free(cleartext);
            return;
        }
        
        int priority = 0;
        if (qos) {
            priority = ieee_packet[24];
        }
        
        michael_mic(sta_data[current_i]->PTK+offset2mic_key, dest_addr, src_addr, priority, cleartext, content_len-12, mic);
        if(memcmp(&cleartext[content_len-12],mic,8) != 0){
            printf("MIC FAILURE\n");
            free(cleartext);
            return;
        }
#if DEBUG
        else{
            printf("## MIC OK\n");
        }
#endif
        
#if DEBUG
        printf("%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",*(sta_data[current_i]->PTK+offset2mic_key+0),*(sta_data[current_i]->PTK+offset2mic_key+1),*(sta_data[current_i]->PTK+offset2mic_key+2),*(sta_data[current_i]->PTK+offset2mic_key+3),*(sta_data[current_i]->PTK+offset2mic_key+4),*(sta_data[current_i]->PTK+offset2mic_key+5),*(sta_data[current_i]->PTK+offset2mic_key+6),*(sta_data[current_i]->PTK+offset2mic_key+7));
        printf("%02x:%02x:%02x:%02x:%02x:%02x\n",dest_addr[0],dest_addr[1],dest_addr[2],dest_addr[3],dest_addr[4],dest_addr[5]);
        printf("%02x:%02x:%02x:%02x:%02x:%02x\n",src_addr[0],src_addr[1],src_addr[2],src_addr[3],src_addr[4],src_addr[5]);
        printf("%02x\n",priority);
        printf("%d ... %d \n",content_len-12, offset2mic_key);
        printf("%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",cleartext[content_len-12+0],cleartext[content_len-12+1],cleartext[content_len-12+2],cleartext[content_len-12+3],cleartext[content_len-12+4],cleartext[content_len-12+5],cleartext[content_len-12+6],cleartext[content_len-12+7]);
        printf("%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",mic[0],mic[1],mic[2],mic[3],mic[4],mic[5],mic[6],mic[7]);
#endif
        
        
        //Now the packet is decrypted correctly
        //Let's peek inside the packet!
        //Is it an ARP packet or an IP packet?
        u_char * netPacket = cleartext + 6; //in LLC
        
        printf("--->%02x:%02x\n",netPacket[0],netPacket[1]);
        
        if(netPacket[0]==0x08 && netPacket[1]==0x06){
            //ARP
            u_char * arp_packet = netPacket+2;
            printf("ARP packet ");
            
            if(arp_packet[0]==0x00 && arp_packet[1]==0x01) //HW type == Ethernet
                if(arp_packet[2]==0x08 && arp_packet[3]==0x00){ //Protocol type == IPv4
                    int op_code = arp_packet[6]*256 + arp_packet[7];
                    
                    u_char targetIP[4], senderIP[4], senderMAC[6];
                    memcpy(senderMAC,&arp_packet[8],6);
                    memcpy(senderIP,&arp_packet[14],4);
                    memcpy(targetIP,&arp_packet[24],4);
                    
                    char c_targetIP[INET_ADDRSTRLEN];
                    char c_senderIP[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, targetIP, c_targetIP, INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, senderIP, c_senderIP, INET_ADDRSTRLEN);
                    
                    u_char broadcast[6]={255,255,255,255,255,255};

                    if (memcmp(dest_addr, broadcast, 6)==0) {
                        printf("(Gratuitous)");
                    }
                    if (op_code==1) {//request
                        printf("Request: Who has %s? Tell %s", c_targetIP, c_senderIP);
                    }
                    if (op_code==2) {//reply
                        printf("Reply: %s is at %02x:%02x:%02x:%02x:%02x:%02x", c_senderIP, senderMAC[0], senderMAC[1], senderMAC[2], senderMAC[3], senderMAC[4], senderMAC[5]);
                    }
                }
            printf("\n");
            
        }
        if(netPacket[0]==0x08 && netPacket[1]==0x00){
            //IPv4
            u_char * ip_packet = netPacket+2;
            u_char ipSRC[4];
            u_char ipDST[4];
            memcpy(ipSRC,&ip_packet[12],4);
            memcpy(ipDST,&ip_packet[16],4);
            
            char c_ipSRC[INET_ADDRSTRLEN];
            char c_ipDST[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, ipSRC, c_ipSRC, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, ipDST, c_ipDST, INET_ADDRSTRLEN);
            printf("IP packet from %s to %s ",c_ipSRC,c_ipDST);
            
            switch (ip_packet[9]) {
                case 1:
                    printf("(ICMP)");
                    break;
                case 2:
                    printf("(IGMP)");
                    break;
                case 6:
                    printf("(TCP)");
                    break;
                case 17:
                    printf("(UDP)");
                    break;
                default:
                    break;
            }
            printf("\n");
        }
    }
    
    return;
}


void open_eapol(const u_char *eapol_packet,u_char *address_1,u_char *address_2,u_char *address_3, int current_i){
    int packet_type=(int)(u_char)eapol_packet[1];
    
    if(packet_type==3){ //EAPOL key
        u_char key_information[2];
        memcpy(key_information, eapol_packet+5, 2*sizeof(u_char));
        
        //printf("%02x%02x\n",key_information[0],key_information[1]);
        
        int key_descriptor_version = (int)(key_information[1] & 0x7);
        int key_type = (int) ((key_information[1] & 0x8)>>3);
        int install = (int) ((key_information[1] & 0x40)>>6);
        int key_ack = (int) ((key_information[1] & 0x80)>>7);
        
        int key_MIC = (int) ((key_information[0] & 0x1));
        int secure = (int) ((key_information[0] & 0x2)>>1);
        int error = (int) ((key_information[0] & 0x4)>>2);
        int request = (int) ((key_information[0] & 0x8)>>3);
        int encrypted_key_data = (int) ((key_information[0] & 0x10)>>4);
        
        //int index;
        //        printf("%d\n",key_descriptor_version);
        //        printf("%d\n",key_type);
        //        printf("%d\n",install);
        //        printf("%d\n",key_ack);
        //        printf("\n%d\n",key_MIC);
        //        printf("%d\n",secure);
        //        printf("%d\n",error);
        //        printf("%d\n",request);
        //        printf("%d\n",encrypted_key_data);
        
        int key_length=(u_int)(u_char)eapol_packet[8]+(u_int)(u_char)eapol_packet[7]*16*16;
        //printf("key_length: %d\n",key_length);
        
        u_char key_nonce[32];
        memcpy(key_nonce, eapol_packet+17, 32*sizeof(u_char));
        
        switch (classify_eapol_key(key_MIC,key_ack,install,key_type, key_nonce)) {
            case MESSAGE_1:
                printf("EAPOL KEY message 1\n");
                
                memcpy(sta_data[current_i]->authenticator, address_3, 6 * sizeof(u_char));
                memcpy(sta_data[current_i]->ANonce, key_nonce, 32 * sizeof(u_char));
                sta_data[current_i]->state = 0;
                
                
#if VERBOSE
                printf("Authenticator");
                print_exString(sta_data[current_i]->authenticator, 6);
                printf("Supplicant");
                print_exString(sta_data[current_i]->supplicant, 6);
                printf("Anonche");
                print_exString(sta_data[current_i]->ANonce, 32);
#endif
                
                
                break;
            case MESSAGE_2:
                printf("EAPOL KEY message 2\n");
                if(current_i >= 0){
                    memcpy(sta_data[current_i]->SNonce, key_nonce, 32 * sizeof(u_char));
                }
                break;
            case MESSAGE_3:
                printf("EAPOL KEY message 3\n");
                generate_ptk(current_i);
                
                int dimEAPOL = 256*eapol_packet[2]+eapol_packet[3]+ 4;
                u_char *tempEAPOL=malloc(sizeof(u_char)*dimEAPOL);
                if(!tempEAPOL){
                    printf("Cannot allocate memory to verify PTK.\n");
                    return;
                }
                
                u_char keymic[16];
                memcpy(keymic, eapol_packet+81, 16);
                
                u_char calcmic[20];
                memcpy(tempEAPOL, eapol_packet, dimEAPOL);
                memset(tempEAPOL+81, 0, 16); // keymic is calculated without keymic
                
                if(key_descriptor_version == 1){ // TKIP
                    HMAC(EVP_md5(), sta_data[current_i]->PTK, 16, tempEAPOL, dimEAPOL, calcmic, NULL);
                }
                else{ // AES (CCMP)
                    HMAC(EVP_sha1(), sta_data[current_i]->PTK, 16, tempEAPOL, dimEAPOL, calcmic, NULL);
                }
                
                
                if(memcmp(keymic,calcmic,16)==0){
                    sta_data[current_i]->state=1;
                    printf("PTK is valid");
                }else{
                    sta_data[current_i]->state=0;
                    printf("PTK is NOT valid");
                }
                break;
            case MESSAGE_4:
                printf("EAPOL KEY message 4\n");
                break;
            default:
                break;
        }
        
        printf("\n");
    }
}

eapolKeyType classify_eapol_key(int key_MIC, int key_ack, int install, int key_type, u_char * Nonce){
    //EAPOL-Key(S, M, A, I, K, SM, KeyRSC, ANonce/SNonce, MIC, DataKDs)
    //S=secure
    //M=key_mic
    //A=key_ack
    //I=install
    //K=key_type
    
    if ((key_MIC==0)&&(key_ack==1)&&(install==0)&&(key_type==1)) {
        //Authenticator→Supplicant:EAPOL-Key(0,0,1,0,P,0,0,ANonce,0,DataKD_M1)
        //where DataKD_M1 = 0 or PMKID for PTK generation, or PMKID KDE (for sending SMKID) for STK generation
        return MESSAGE_1;
    }
    else if ((key_MIC==1)&&(key_ack==0)&&(install==0)&&(key_type==1)){
        u_char null_32[32]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
        if (memcmp(Nonce, null_32, 32)!=0) {
            //Supplicant→Authenticator:EAPOL-Key(0,1,0,0,P,0,0,SNonce,MIC,DataKD_M2)
            //where DataKD_M2 = RSNIE for creating PTK generation or peer RSNIE, Lifetime KDE, SMKID KDE (for sending SMKID) for STK generation
            return MESSAGE_2;
        }else{
            //Supplicant→Authenticator:EAPOL-Key(1,1,0,0,P,0,0,0,MIC,DataKD_M4)
            //where DataKD_M4 = 0.
            return MESSAGE_4;
        }
    }
    else if ((key_MIC==1)&&(key_ack==1)&&(install==1)&&(key_type==1)){
        //Authenticator→Supplicant: EAPOL-Key(1,1,1,1,P,0,KeyRSC,ANonce,MIC,DataKD_M3)
        //where DataKD_M3 = RSNIE,GTK[N] for creating PTK generation or initiator RSNIE, Lifetime KDE for STK generation
        return MESSAGE_3;
    }
    else return -1;
}


int new_sta(u_char *sta_address){
    int i;
    for(i = 0; i < num_sta; i++){
        if(memcmp(sta_data[i]->supplicant, sta_address, 6 * sizeof(u_char))==0)
            return 0;
    }
    return 1;
}

int get_index(u_char *sta_address){
    int i;
    for(i = 0; i < num_sta; i++){
        if(memcmp(sta_data[i]->supplicant, sta_address, 6 * sizeof(u_char))==0)
            return i;
    }
    return -1;
}

