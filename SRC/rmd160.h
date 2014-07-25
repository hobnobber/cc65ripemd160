/*
Mark Hoblit
hobnobber@gmail.com
http://mark.hoblit.net/crypto/
*/
#ifndef _RMD160_H
#define _RMD160_H

#ifndef uint8
#define uint8  unsigned char
#endif

#ifndef uint32
#define uint32 unsigned long int
#endif

typedef struct
{
    uint32 total[2];
    uint32 state[5];
    uint8 buffer[64];
}
rmd160_context;

void rmd160_starts( rmd160_context *ctx );
void rmd160_update( rmd160_context *ctx, uint8 *input, uint32 length );
void rmd160_finish( rmd160_context *ctx, uint8 digest[20] );

#endif /* rmd160.h */