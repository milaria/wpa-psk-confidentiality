//
//  util_functions.c
//  NetSec
//
//  Created by Ilaria Martinelli on 22/08/14.
//  Copyright (c) 2014 Ilaria Martinelli. All rights reserved.
//

#include "util_functions.h"

void print_exString(u_char * str, int len){
    int i;
    for (i = 0; i < len; i++) {
        if(i%8 == 0) printf(" ");
        if(i%32 == 0) printf("\n");
        printf("%02x",str[i]);
    }
    printf("\n");
}