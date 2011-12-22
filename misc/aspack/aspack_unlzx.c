#include <stdlib.h>
#include <stdio.h>
#include <strings.h> // for bzero()

#include "lzxdec.c"

// based on ASPack Unpacker v1.00 by Dr.Golova (thx! :)

/* error codes for unpacker thread */
#define ERR_OK             (0)
#define ERR_NO_FILE        (1)
#define ERR_FILE_OPEN      (2)
#define ERR_NO_MEM         (3)
#define ERR_CANT_MAP       (4)
#define ERR_FILE_CREATE    (5)
#define ERR_FILE_WRITE     (6)
#define ERR_COPY_OVL       (7)
#define ERR_CORRUPT        (8)
#define ERR_UNKNOWN        (9)
#define ERR_SKIPPED        (10)
#define ERR_UNPACK         (11)
#define ERR_FAILED         (12)


void write_result(void*buf, int size){
    fwrite(buf,1,size,stdout);
}

int unpack(BYTE*packed_data, size_t packed_size, size_t unpacked_size){
    LZX_CONTEXT LZX;
    BYTE* unpacked_data = NULL;
    size_t decoded_size;

    bzero(&LZX, sizeof(LZX));

    if ( NULL == (unpacked_data = calloc(1, unpacked_size + 300)) ){
        perror("no mem");
        return(ERR_NO_MEM);
    }

    decoded_size = DecodeLZX(&LZX, packed_data, unpacked_data, packed_size, unpacked_size);
    if ( decoded_size < 0 || decoded_size < unpacked_size ) {
        free(unpacked_data);
        fprintf(stderr,"ERR_UNPACK\n");
        return(ERR_UNPACK);
    }

    write_result(unpacked_data, decoded_size);
    free(unpacked_data);
    return 0;
}

int main(int argc, char*argv[]){
    size_t packed_size, unpacked_size;
    BYTE* packed_data = NULL;
    int r;

    if(argc != 3){
        fprintf(stderr, "ASPack unLZX\n");
        fprintf(stderr, "usage: %s <packed_size> <unpacked_size>\n", argv[0]);
        fprintf(stderr, "(data is read from stdin and written to stdout)\n", argv[0]);
        return 1;
    }

    sscanf(argv[1],"%zu",&packed_size);
    if( packed_size < 1 || packed_size > 0x10000000 ){ // 256 Mb max
        fprintf(stderr, "invalid packed_size: %zu\n", packed_size);
        return 1;
    }

    sscanf(argv[2],"%zu",&unpacked_size);
    if( unpacked_size < 1 || unpacked_size > 0x10000000 ){ // 256 Mb max
        fprintf(stderr, "invalid unpacked_size: %zu\n", unpacked_size);
        return 1;
    }

    /* alloc buffer */
    if ( NULL == (packed_data = calloc(1, packed_size + 300)) ){
        perror("no mem");
        return(ERR_NO_MEM);
    }

    if( packed_size != fread(packed_data, 1, packed_size, stdin)){
        free(packed_data);
        perror("read");
        return(ERR_NO_FILE);
    }

    r = unpack(packed_data, packed_size, unpacked_size);
    free(packed_data);
    return r;
}
