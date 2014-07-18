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
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <openssl/hmac.h>

#include "passphrase2PSK.h"
#include "PRF.h"

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

typedef struct handshake_data{
    u_char supplicant[6];
    u_char authenticator[6];
    u_char ANonce[32]; //32byte
    u_char SNonce[32]; //32byte
    u_char IV[16];
    u_char PTK[32];
    int state;//1 if finished
}Handshake_data, * Phandshake_data;

typedef enum{
    MESSAGE_1,
    MESSAGE_2,
    MESSAGE_3,
    MESSAGE_4
}eapolKeyType;

#define MAX_NUM_STA 10
Phandshake_data sta_data[MAX_NUM_STA];
int num_sta=0;
u_char * PSK;

void got_packet_radiotap(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void open_ieee_packet(const u_char *ieee_packet);
void open_llc_packet(const u_char *llc_packet,u_char *address_1,u_char *address_2,u_char *address_3);
void open_eapol(const u_char *eapol_packet,u_char *address_1,u_char *address_2,u_char *address_3);
void message_1(const u_char *eapol_key,u_char *address_1,u_char *address_2,u_char *address_3);
char* address_format(char address_1[6]);
int new_sta(u_char *address_1);
eapolKeyType classify_eapol_key(int secure, int key_MIC, int key_ack, int install, int key_type);
int get_index(u_char *sta_address);
void print_exString(u_char * str, int len);
void generate_ptk(int sta_index);



int main(int argc, char **argv){
    unsigned char * output1 = (unsigned char *)malloc(80*sizeof(char));
    PRF("Jefe", 4, "prefix", 6, "what do ya want for nothing?", 28, output1, 80);
    
    print_exString(output1, 80);
    
    exit(EXIT_SUCCESS);
    
    char* Passphrase;
    u_char* SSID;
    int SSIDLength;
    PSK = (u_char *) malloc(32);
    
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */
    char* fname;
    
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
	}
    
    SSIDLength = strlen(SSID);
    u_char * output = (u_char *) malloc(40);
    PasswordHash(Passphrase, SSID, SSIDLength, output);
    memcpy(PSK, output, 32*sizeof(u_char));
    
    printf("PSK: ");
    print_exString(PSK, 32);
    printf("\n");
    
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
    printf("\nPacket number %d, length: %d\n", count, header->len);
    
    
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
    
    u_char address_1[6];
    memcpy(address_1, ieee_packet+4, 6*sizeof(u_char));
    u_char address_2[6];
    memcpy(address_2, ieee_packet+4+6, 6*sizeof(u_char));
    u_char address_3[6];
    memcpy(address_3, ieee_packet+4+6+6, 6*sizeof(u_char));
    
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
        if(!protected)
        {
            //Address 1 always holds the receiver address of the intended receiver (or, in the case of multicast frames, receivers)
            //Address 2 always holds the address of the STA that is transmitting the frame.
            const u_char * llc_packet = ieee_packet+mac_frame_header_length;
            open_llc_packet(llc_packet,address_1,address_2,address_3);
        }
    }
    
    return;
}

void open_llc_packet(const u_char *llc_packet,u_char *address_1,u_char *address_2,u_char *address_3){
    //int individual = (int) ((llc_packet[0] & 0x80) >> 7);
    //int command = (int) ((llc_packet[0] & 0x80) >> 7);
    //For I/G = 0 the address is individual and for I/G=1 it's a group address.
    u_char type[2];
    memcpy(type, llc_packet+6, 2*sizeof(u_char));
    //printf("%2x%2x\n",type[0],type[1]);
    
    if((type[0]==0x88) && (type[1]==0x8e)){//EAPOL!
        //printf("EAPOL");
        int llc_header_length=8;
        open_eapol(llc_packet+llc_header_length,address_1,address_2,address_3);
        
    }
}

void open_eapol(const u_char *eapol_packet,u_char *address_1,u_char *address_2,u_char *address_3){
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
                printf("message 1");
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
                printf("message 2");
                index = get_index(address_2);
                if(index >= 0){
                    memcpy(sta_data[index]->SNonce, key_nonce, 32 * sizeof(u_char));
                    //control the MIC?
                    generate_ptk(index);
                }
                break;
            case MESSAGE_3:
                printf("message 3");
                index = get_index(address_1);
                //control the MIC?
                break;
            case MESSAGE_4:
                printf("message 4");
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


void print_exString(u_char * str, int len){
    int i;
    for (i = 0; i < len; i++) {
        if(i%8 == 0) printf(" ");
        if(i%32 == 0) printf("\n");
        printf("%02x",str[i]);
    }
    printf("\n");
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

void generate_ptk(sta_index){
    //PRF-X(PMK, “Pairwise key expansion”, Min(AA,SPA) || Max(AA,SPA) || Min(ANonce,SNonce) || Max(ANonce,SNonce))
    
    u_char * AA = sta_data[sta_index]->authenticator;
    u_char * SPA = sta_data[sta_index]->supplicant;
    u_char * ANonce = sta_data[sta_index]->ANonce;
    u_char * SNonce = sta_data[sta_index]->SNonce;
    
    //data = Min(AA,SPA) || Max(AA,SPA) || Min(ANonce,SNonce) || Max(ANonce,SNonce)
    int data_len = 76; //6+6+32+32
    u_char *data = (u_char *) malloc(data_len * sizeof(u_char));
    if(memcmp(SPA,AA, 6) > 0){
        memcpy(data, AA, 6);
        memcpy(data+6, SPA, 6);
    }else{
        memcpy(data, SPA, 6);
        memcpy(data+6, AA, 6);
    }
    
    if(memcmp(ANonce,SNonce, 32) > 0){
        memcpy(data+12, SNonce, 32);
        memcpy(data+12+32, ANonce, 32);
    }else{
        memcpy(data+12, ANonce, 32);
        memcpy(data+12+32, SNonce, 32);
    }
    
    int key_len = 32; //??
    
    u_char *prefix = "Pairwise key expansion";
    int prefix_len = strlen(prefix);
    
    int len = 80;
    u_char *output = (u_char *)malloc(len);
    
    PRF(PSK, key_len, prefix, prefix_len, data, data_len, output, len);
    print_exString(output, 64);
    
    memcpy(sta_data[sta_index]->PTK, output, 32 * sizeof(u_char));
    printf("\n");
    
}