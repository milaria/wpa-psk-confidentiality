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
void open_ieee_packet(const u_char *ieee_packet);
void open_llc_packet(const u_char *llc_packet,u_char *address_1,u_char *address_2,u_char *address_3,int current_i);
void open_eapol(const u_char *eapol_packet,u_char *address_1,u_char *address_2,u_char *address_3,int current_i);
void message_1(const u_char *eapol_key,u_char *address_1,u_char *address_2,u_char *address_3,int current_i);
char* address_format(char address_1[6]);
int new_sta(u_char *address_1);
eapolKeyType classify_eapol_key(int secure, int key_MIC, int key_ack, int install, int key_type);
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
    
    /*
     unsigned char * output1 = (unsigned char *)malloc(80*(int)sizeof(char));
     PRF((unsigned char *)"Jefe", 4, (unsigned char *)"prefix", 6, (unsigned char *)"what do ya want for nothing?", 28, output1, 80);
     
     print_exString(output1, 80);*/
    
    
    
    /*
	if (argc == 4) {
		fname = argv[1];
        SSID = (u_char *) argv[2];
        Passphrase = argv[3];
	}
    else if (argc == 3){
        SSID = (u_char *) argv[1];
        Passphrase = argv[2];
        fname = NULL;
    }
	else {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		exit(EXIT_FAILURE);
	}*/
    
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
    
    
    if((pcap_datalink(handle)) == DLT_IEEE802_11_RADIO) //maybe check also for PRISM
        pcap_loop(handle, -1, got_packet_radiotap, NULL);
    
    return 0;
}

void got_packet_radiotap(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    static int count = 1;
#if VERBOSE
    printf("\nPacket number %d, length: %d\n", count, header->len);
#else
    printf("\n[%d]", count);
#endif
    
    
    u_char header_revision = (u_char)packet[0];
    //printf("header_revision:%2x\n",header_revision);
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
    
    const u_char * ieee_packet = packet+header_length;
    open_ieee_packet(ieee_packet);
    
    
	count++;
    return;
}

void open_ieee_packet(const u_char *ieee_packet){
    u_char proto_type_subtype = (u_char)ieee_packet[0];
    //printf("frame_control:%2x\n",proto_type_subtype);
    int protocol_version = (int)((proto_type_subtype & 0x3));
    int type = (int)((proto_type_subtype & 0xC) >> 2);
    int subtype = (int)((proto_type_subtype & 0xF0) >> 4);
    int qos = (int)(type == 2) & ((proto_type_subtype & 0xF0) >> 7);
    //printf("qos: %d\n",qos);
    
    //printf("protocol_version:%d\n",protocol_version);
    if(protocol_version != 0) return; //not standard -> controllare
    
    //printf("type:%d\n",type);
    //printf("subtype:%d\n",subtype);
    
    u_char flags = (u_char)ieee_packet[1];
    int to_ds = (int)(flags & 0x1);
    int from_ds = (int)((flags & 0x2) >> 1);
    int protected = (int)((flags & 0x40) >> 6);
    //The Protected Frame field is set to 1 only within data frames and within management frames of subtype Authentication.
    
    //printf("flags: %2x\n",flags);
    //printf("protected %d\n",protected);
    
    //Note that Address 1 always holds the receiver address of the intended receiver (or, in the case of multicast frames, receivers), and that Address 2 always holds the address of the STA that is transmitting the frame.
    u_char address_1[6];
    memcpy(address_1, ieee_packet+4, 6*sizeof(u_char));
    u_char address_2[6];
    memcpy(address_2, ieee_packet+4+6, 6*sizeof(u_char));
    u_char address_3[6];
    memcpy(address_3, ieee_packet+4+6+6, 6*sizeof(u_char));
    
    u_char * bssid, * stmac;
    
    if (to_ds == 0 && from_ds == 1) {
        stmac = address_2;
        bssid = address_1;
    }else{
        stmac = address_1;
        bssid = address_2;
    }
    
    int current_i = get_index(stmac);
    if(current_i == -1 && num_sta<MAX_NUM_STA){ //new station
        num_sta++;
        current_i = num_sta - 1;
        sta_data[current_i] = (Phandshake_data)malloc(sizeof(Handshake_data));
        memcpy(sta_data[current_i]->supplicant, stmac, 6 * sizeof(u_char));
        sta_data[current_i]->state = 0;
    }
    
    //printf("\%2x:\%2x:\%2x:\%2x:\%2x:\%2x\n",address_1[0],address_1[1],address_1[2],address_1[3],address_1[4],address_1[5]);
    
    int mac_frame_header_length;
    if(!(from_ds & to_ds)) { //there's no Address 4
        if(!qos) {
            mac_frame_header_length=24;//byte
        }
        else{
            mac_frame_header_length=26;//byte
        }
    }//da controllare
    
    if(type==2 & subtype==0){//data type
        if(!protected) {
            //Address 1 always holds the receiver address of the intended receiver (or, in the case of multicast frames, receivers)
            //Address 2 always holds the address of the STA that is transmitting the frame.
            const u_char * llc_packet = ieee_packet+mac_frame_header_length;
            open_llc_packet(llc_packet,address_1,address_2,address_3,current_i);
        }
        else{//protected... trying to decrypt
            /*
             The ExtIV bit in the Key ID octet indicates the presence or absence of an extended IV. If the ExtIV bit is 0, only the nonextended IV is transferred. If the ExtIV bit is 1, an extended IV of 4 octets follows the original IV. For TKIP the ExtIV bit shall be set, and the Extended IV field shall be supplied. The ExtIV bit shall be 0 for WEP frames.
             */
            if (sta_data[current_i]->state == 0) { //key not valid
                return;
            }
            
            const u_char * TKIP_par = ieee_packet + mac_frame_header_length;
            
            u_short IV16 = 256 * TKIP_par[0] + TKIP_par[2]; //TSC1*256 + TSC0
            u_long IV32 = TKIP_par[4] + 256 * (TKIP_par[5] + 256 * (TKIP_par[6] + 256 * TKIP_par[7])); //TSC2 TSC3 TSC4 TSC5
            
            u_short P1K[80];
            u_char RC4KEY[16];
            u_char * TA = address_2;
            
            Phase1(P1K, sta_data[current_i]->PTK+32, TA, IV32); // sta_data[current_i]->PTK+32 = TK
            Phase2(RC4KEY, sta_data[current_i]->PTK+32, P1K, IV16);
            /*
            int cleartext_len = packetHeader.caplen-packetPos-8;
            u_char *cleartext = rc4(pacchetto80211 + packetPos + 8,lunghezzaCleartext, RC4KEY, 16);
            
            u_int crcCLEAR = crc32buf(cleartext, lunghezzaCleartext-4); // 12: 4 (CRC) + IV + EXTIV
            u_int ICV = cleartext[lunghezzaCleartext-4]+256*(cleartext[lunghezzaCleartext-3]
                                                             +256*(cleartext[lunghezzaCleartext-2]+256*cleartext[lunghezzaCleartext-1]));
            if(crcCLEAR!=ICV){
                printf("ICV FAILURE %d!\n",statistiche.letti);
                // se ICV non e' esatto, la decifratura non e' andata bene o il pacchetto e' errato
                free(cleartext);
                continue;
            }
             */

            
        }
    }
    
    return;
}

void open_llc_packet(const u_char *llc_packet,u_char *address_1,u_char *address_2,u_char *address_3, int current_i){
    //int individual = (int) ((llc_packet[0] & 0x80) >> 7);
    //int command = (int) ((llc_packet[0] & 0x80) >> 7);
    //For I/G = 0 the address is individual and for I/G=1 it's a group address.
    u_char type[2];
    memcpy(type, llc_packet+6, 2*sizeof(u_char));
    //printf("%2x%2x\n",type[0],type[1]);
    
    if((type[0]==0x88) && (type[1]==0x8e)){//EAPOL!
        //printf("EAPOL");
        int llc_header_length=8;
        open_eapol(llc_packet+llc_header_length,address_1,address_2,address_3, current_i);
        
    }
}

void open_eapol(const u_char *eapol_packet,u_char *address_1,u_char *address_2,u_char *address_3, int current_i){
    int packet_type=(int)(u_char)eapol_packet[1];
    //printf("%d\n",packet_type);//if packet_type==3 EAPOL key
    
    if(packet_type==3){
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
        
        int index;
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
        
        switch (classify_eapol_key(secure,key_MIC,key_ack,install,key_type)) {
            case MESSAGE_1:
                printf("EAPOL KEY message 1");
                //allocation of stations data
                if(num_sta == 0){
                    sta_data[0] = (Phandshake_data) malloc(sizeof(Handshake_data));
                    num_sta = 1;
                    index = num_sta - 1;
                }
                else if(new_sta(address_1)){
                    sta_data[num_sta] = (Phandshake_data) malloc(sizeof(Handshake_data));
                    num_sta++;
                    index = num_sta - 1;
                }
                else index = get_index(address_1); //double message 1 (ERROR OCCURRED)
                memcpy(sta_data[index]->authenticator, address_3, 6 * sizeof(u_char));
                memcpy(sta_data[index]->supplicant, address_1, 6 * sizeof(u_char));
                memcpy(sta_data[index]->ANonce, key_nonce, 32 * sizeof(u_char));
                sta_data[index]->state = 0;
                break;
            case MESSAGE_2:
                printf("EAPOL KEY message 2");
                index = get_index(address_2);
                if(index >= 0){
                    memcpy(sta_data[index]->SNonce, key_nonce, 32 * sizeof(u_char));
                    //control the MIC?
                    generate_ptk(index);
                }
                break;
            case MESSAGE_3:
                printf("EAPOL KEY message 3");
                index = get_index(address_1);
                //control the MIC?
                break;
            case MESSAGE_4:
                printf("EAPOL KEY message 4");
                index = get_index(address_2);
                sta_data[index]->state = 1;
                //control the MIC?
                break;
            default:
                break;
        }
        
        printf("\n");
    }
}

eapolKeyType classify_eapol_key(int secure, int key_MIC, int key_ack, int install, int key_type){
    //EAPOL-Key(S, M, A, I, K, SM, KeyRSC, ANonce/SNonce, MIC, DataKDs)
    //S=secure
    //M=key_mic
    //A=key_ack
    //I=install
    //K=key_type
    
    if ((secure==0)&&(key_MIC==0)&&(key_ack==1)&&(install==0)&&(key_type==1)) {
        //Authenticator→Supplicant:EAPOL-Key(0,0,1,0,P,0,0,ANonce,0,DataKD_M1)
        //where DataKD_M1 = 0 or PMKID for PTK generation, or PMKID KDE (for sending SMKID) for STK generation
        return MESSAGE_1;
    }
    else if ((secure==0)&&(key_MIC==1)&&(key_ack==0)&&(install==0)&&(key_type==1)){
        //Supplicant→Authenticator:EAPOL-Key(0,1,0,0,P,0,0,SNonce,MIC,DataKD_M2)
        //where DataKD_M2 = RSNIE for creating PTK generation or peer RSNIE, Lifetime KDE, SMKID KDE (for sending SMKID) for STK generation
        return MESSAGE_2;
    }
    else if ((secure==1)&&(key_MIC==1)&&(key_ack==1)&&(install==1)&&(key_type==1)){
        //Authenticator→Supplicant: EAPOL-Key(1,1,1,1,P,0,KeyRSC,ANonce,MIC,DataKD_M3)
        //where DataKD_M3 = RSNIE,GTK[N] for creating PTK generation or initiator RSNIE, Lifetime KDE for STK generation
        return MESSAGE_3;
    }
    else if ((secure==1)&&(key_MIC==1)&&(key_ack==0)&&(install==0)&&(key_type==1)){
        //Supplicant→Authenticator:EAPOL-Key(1,1,0,0,P,0,0,0,MIC,DataKD_M4)
        //where DataKD_M4 = 0.
        return MESSAGE_4;
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

