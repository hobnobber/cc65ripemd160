/*
Mark Hoblit
hobnobber@gmail.com
http://mark.hoblit.net/crypto/
*/
/*
 *  RIPEMD-160 implementation
 *
 *  Copyright (C) 2014  Mark Hoblit
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <string.h>
#include "rmd160.h"

void rmd160_starts( rmd160_context *ctx )
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;    
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xc3d2e1f0;
}

uint32 ROL(uint32 x, uint32 n)
{
    return (((x) << (n)) | ((x) >> (32-(n))));
}

#define F(x, y, z)        ((x) ^ (y) ^ (z)) 
#define G(x, y, z)        (((x) & (y)) | (~(x) & (z))) 
#define H(x, y, z)        (((x) | ~(y)) ^ (z))
#define I(x, y, z)        (((x) & (z)) | ((y) & ~(z))) 
#define J(x, y, z)        ((x) ^ ((y) | ~(z)))

void F1(uint32 *a,uint32 b,uint32 *c,uint32 d,uint32 e,uint32 x,uint32 s)
{
    *a += F((b), (*c), (d)) + (x);
    *a = ROL((*a), (s)) + (e);
    *c = ROL((*c), 10);
}

void G1(uint32 *a,uint32 b,uint32 *c,uint32 d,uint32 e,uint32 x,uint32 s)
{
    *a += G((b), (*c), (d)) + (x) + 0x5a827999;
    *a = ROL((*a), (s)) + (e);
    *c = ROL((*c), 10);
}

void H1(uint32 *a,uint32 b,uint32 *c,uint32 d,uint32 e,uint32 x,uint32 s)
{
    *a += H((b), (*c), (d)) + (x) + 0x6ed9eba1;
    *a = ROL((*a), (s)) + (e);
    *c = ROL((*c), 10);
}

void I1(uint32 *a,uint32 b,uint32 *c,uint32 d,uint32 e,uint32 x,uint32 s)
{
    *a += I((b), (*c), (d)) + (x) + 0x8f1bbcdc;
    *a = ROL((*a), (s)) + (e);
    *c = ROL((*c), 10);
}

void J1(uint32 *a,uint32 b,uint32 *c,uint32 d,uint32 e,uint32 x,uint32 s)
{
    *a += J((b), (*c), (d)) + (x) + 0xa953fd4e;
    *a = ROL((*a), (s)) + (e);
    *c = ROL((*c), 10);
}

void F2(uint32 *a,uint32 b,uint32 *c,uint32 d,uint32 e,uint32 x,uint32 s)
{
    *a += F((b), (*c), (d)) + (x);
    *a = ROL((*a), (s)) + (e);
    *c = ROL((*c), 10);
}

void G2(uint32 *a,uint32 b,uint32 *c,uint32 d,uint32 e,uint32 x,uint32 s)
{
    *a += G((b), (*c), (d)) + (x) + 0x7a6d76e9;
    *a = ROL((*a), (s)) + (e);
    *c = ROL((*c), 10);
}

void H2(uint32 *a,uint32 b,uint32 *c,uint32 d,uint32 e,uint32 x,uint32 s)
{
    *a += H((b), (*c), (d)) + (x) + 0x6d703ef3;
    *a = ROL((*a), (s)) + (e);
    *c = ROL((*c), 10);
}

void I2(uint32 *a,uint32 b,uint32 *c,uint32 d,uint32 e,uint32 x,uint32 s)
{
    *a += I((b), (*c), (d)) + (x) + 0x5c4dd124;
    *a = ROL((*a), (s)) + (e);
    *c = ROL((*c), 10);
}

void J2(uint32 *a,uint32 b,uint32 *c,uint32 d,uint32 e,uint32 x,uint32 s)
{
    *a += J((b), (*c), (d)) + (x) + 0x50a28be6;
    *a = ROL((*a), (s)) + (e);
    *c = ROL((*c), 10);
}

void rmd160_process( rmd160_context *ctx, uint32 W[16] )
{
    uint32 A1, B1, C1, D1, E1, A2, B2, C2, D2, E2;
    
    A1 = A2 = ctx->state[0];
    B1 = B2 = ctx->state[1];
    C1 = C2 = ctx->state[2];
    D1 = D2 = ctx->state[3];
    E1 = E2 = ctx->state[4];
    
    /* round 1 */
    F1(&A1, B1, &C1, D1, E1, W[ 0], 11);
    F1(&E1, A1, &B1, C1, D1, W[ 1], 14);
    F1(&D1, E1, &A1, B1, C1, W[ 2], 15);
    F1(&C1, D1, &E1, A1, B1, W[ 3], 12);
    F1(&B1, C1, &D1, E1, A1, W[ 4],  5);
    F1(&A1, B1, &C1, D1, E1, W[ 5],  8);
    F1(&E1, A1, &B1, C1, D1, W[ 6],  7);
    F1(&D1, E1, &A1, B1, C1, W[ 7],  9);
    F1(&C1, D1, &E1, A1, B1, W[ 8], 11);
    F1(&B1, C1, &D1, E1, A1, W[ 9], 13);
    F1(&A1, B1, &C1, D1, E1, W[10], 14);
    F1(&E1, A1, &B1, C1, D1, W[11], 15);
    F1(&D1, E1, &A1, B1, C1, W[12],  6);
    F1(&C1, D1, &E1, A1, B1, W[13],  7);
    F1(&B1, C1, &D1, E1, A1, W[14],  9);
    F1(&A1, B1, &C1, D1, E1, W[15],  8);
    
    /* round 2 */
    G1(&E1, A1, &B1, C1, D1, W[ 7],  7);
    G1(&D1, E1, &A1, B1, C1, W[ 4],  6);
    G1(&C1, D1, &E1, A1, B1, W[13],  8);
    G1(&B1, C1, &D1, E1, A1, W[ 1], 13);
    G1(&A1, B1, &C1, D1, E1, W[10], 11);
    G1(&E1, A1, &B1, C1, D1, W[ 6],  9);
    G1(&D1, E1, &A1, B1, C1, W[15],  7);
    G1(&C1, D1, &E1, A1, B1, W[ 3], 15);
    G1(&B1, C1, &D1, E1, A1, W[12],  7);
    G1(&A1, B1, &C1, D1, E1, W[ 0], 12);
    G1(&E1, A1, &B1, C1, D1, W[ 9], 15);
    G1(&D1, E1, &A1, B1, C1, W[ 5],  9);
    G1(&C1, D1, &E1, A1, B1, W[ 2], 11);
    G1(&B1, C1, &D1, E1, A1, W[14],  7);
    G1(&A1, B1, &C1, D1, E1, W[11], 13);
    G1(&E1, A1, &B1, C1, D1, W[ 8], 12);
    
    /* round 3 */
    H1(&D1, E1, &A1, B1, C1, W[ 3], 11);
    H1(&C1, D1, &E1, A1, B1, W[10], 13);
    H1(&B1, C1, &D1, E1, A1, W[14],  6);
    H1(&A1, B1, &C1, D1, E1, W[ 4],  7);
    H1(&E1, A1, &B1, C1, D1, W[ 9], 14);
    H1(&D1, E1, &A1, B1, C1, W[15],  9);
    H1(&C1, D1, &E1, A1, B1, W[ 8], 13);
    H1(&B1, C1, &D1, E1, A1, W[ 1], 15);
    H1(&A1, B1, &C1, D1, E1, W[ 2], 14);
    H1(&E1, A1, &B1, C1, D1, W[ 7],  8);
    H1(&D1, E1, &A1, B1, C1, W[ 0], 13);
    H1(&C1, D1, &E1, A1, B1, W[ 6],  6);
    H1(&B1, C1, &D1, E1, A1, W[13],  5);
    H1(&A1, B1, &C1, D1, E1, W[11], 12);
    H1(&E1, A1, &B1, C1, D1, W[ 5],  7);
    H1(&D1, E1, &A1, B1, C1, W[12],  5);
    
    /* round 4 */
    I1(&C1, D1, &E1, A1, B1, W[ 1], 11);
    I1(&B1, C1, &D1, E1, A1, W[ 9], 12);
    I1(&A1, B1, &C1, D1, E1, W[11], 14);
    I1(&E1, A1, &B1, C1, D1, W[10], 15);
    I1(&D1, E1, &A1, B1, C1, W[ 0], 14);
    I1(&C1, D1, &E1, A1, B1, W[ 8], 15);
    I1(&B1, C1, &D1, E1, A1, W[12],  9);
    I1(&A1, B1, &C1, D1, E1, W[ 4],  8);
    I1(&E1, A1, &B1, C1, D1, W[13],  9);
    I1(&D1, E1, &A1, B1, C1, W[ 3], 14);
    I1(&C1, D1, &E1, A1, B1, W[ 7],  5);
    I1(&B1, C1, &D1, E1, A1, W[15],  6);
    I1(&A1, B1, &C1, D1, E1, W[14],  8);
    I1(&E1, A1, &B1, C1, D1, W[ 5],  6);
    I1(&D1, E1, &A1, B1, C1, W[ 6],  5);
    I1(&C1, D1, &E1, A1, B1, W[ 2], 12);
    
    /* round 5 */
    J1(&B1, C1, &D1, E1, A1, W[ 4],  9);
    J1(&A1, B1, &C1, D1, E1, W[ 0], 15);
    J1(&E1, A1, &B1, C1, D1, W[ 5],  5);
    J1(&D1, E1, &A1, B1, C1, W[ 9], 11);
    J1(&C1, D1, &E1, A1, B1, W[ 7],  6);
    J1(&B1, C1, &D1, E1, A1, W[12],  8);
    J1(&A1, B1, &C1, D1, E1, W[ 2], 13);
    J1(&E1, A1, &B1, C1, D1, W[10], 12);
    J1(&D1, E1, &A1, B1, C1, W[14],  5);
    J1(&C1, D1, &E1, A1, B1, W[ 1], 12);
    J1(&B1, C1, &D1, E1, A1, W[ 3], 13);
    J1(&A1, B1, &C1, D1, E1, W[ 8], 14);
    J1(&E1, A1, &B1, C1, D1, W[11], 11);
    J1(&D1, E1, &A1, B1, C1, W[ 6],  8);
    J1(&C1, D1, &E1, A1, B1, W[15],  5);
    J1(&B1, C1, &D1, E1, A1, W[13],  6);
    
    /* parallel round 1 */
    J2(&A2, B2, &C2, D2, E2, W[ 5],  8);
    J2(&E2, A2, &B2, C2, D2, W[14],  9);
    J2(&D2, E2, &A2, B2, C2, W[ 7],  9);
    J2(&C2, D2, &E2, A2, B2, W[ 0], 11);
    J2(&B2, C2, &D2, E2, A2, W[ 9], 13);
    J2(&A2, B2, &C2, D2, E2, W[ 2], 15);
    J2(&E2, A2, &B2, C2, D2, W[11], 15);
    J2(&D2, E2, &A2, B2, C2, W[ 4],  5);
    J2(&C2, D2, &E2, A2, B2, W[13],  7);
    J2(&B2, C2, &D2, E2, A2, W[ 6],  7);
    J2(&A2, B2, &C2, D2, E2, W[15],  8);
    J2(&E2, A2, &B2, C2, D2, W[ 8], 11);
    J2(&D2, E2, &A2, B2, C2, W[ 1], 14);
    J2(&C2, D2, &E2, A2, B2, W[10], 14);
    J2(&B2, C2, &D2, E2, A2, W[ 3], 12);
    J2(&A2, B2, &C2, D2, E2, W[12],  6);
    
    /* parallel round 2 */
    I2(&E2, A2, &B2, C2, D2, W[ 6],  9); 
    I2(&D2, E2, &A2, B2, C2, W[11], 13);
    I2(&C2, D2, &E2, A2, B2, W[ 3], 15);
    I2(&B2, C2, &D2, E2, A2, W[ 7],  7);
    I2(&A2, B2, &C2, D2, E2, W[ 0], 12);
    I2(&E2, A2, &B2, C2, D2, W[13],  8);
    I2(&D2, E2, &A2, B2, C2, W[ 5],  9);
    I2(&C2, D2, &E2, A2, B2, W[10], 11);
    I2(&B2, C2, &D2, E2, A2, W[14],  7);
    I2(&A2, B2, &C2, D2, E2, W[15],  7);
    I2(&E2, A2, &B2, C2, D2, W[ 8], 12);
    I2(&D2, E2, &A2, B2, C2, W[12],  7);
    I2(&C2, D2, &E2, A2, B2, W[ 4],  6);
    I2(&B2, C2, &D2, E2, A2, W[ 9], 15);
    I2(&A2, B2, &C2, D2, E2, W[ 1], 13);
    I2(&E2, A2, &B2, C2, D2, W[ 2], 11);
    
    /* parallel round 3 */
    H2(&D2, E2, &A2, B2, C2, W[15],  9);
    H2(&C2, D2, &E2, A2, B2, W[ 5],  7);
    H2(&B2, C2, &D2, E2, A2, W[ 1], 15);
    H2(&A2, B2, &C2, D2, E2, W[ 3], 11);
    H2(&E2, A2, &B2, C2, D2, W[ 7],  8);
    H2(&D2, E2, &A2, B2, C2, W[14],  6);
    H2(&C2, D2, &E2, A2, B2, W[ 6],  6);
    H2(&B2, C2, &D2, E2, A2, W[ 9], 14);
    H2(&A2, B2, &C2, D2, E2, W[11], 12);
    H2(&E2, A2, &B2, C2, D2, W[ 8], 13);
    H2(&D2, E2, &A2, B2, C2, W[12],  5);
    H2(&C2, D2, &E2, A2, B2, W[ 2], 14);
    H2(&B2, C2, &D2, E2, A2, W[10], 13);
    H2(&A2, B2, &C2, D2, E2, W[ 0], 13);
    H2(&E2, A2, &B2, C2, D2, W[ 4],  7);
    H2(&D2, E2, &A2, B2, C2, W[13],  5);
    
    /* parallel round 4 */   
    G2(&C2, D2, &E2, A2, B2, W[ 8], 15);
    G2(&B2, C2, &D2, E2, A2, W[ 6],  5);
    G2(&A2, B2, &C2, D2, E2, W[ 4],  8);
    G2(&E2, A2, &B2, C2, D2, W[ 1], 11);
    G2(&D2, E2, &A2, B2, C2, W[ 3], 14);
    G2(&C2, D2, &E2, A2, B2, W[11], 14);
    G2(&B2, C2, &D2, E2, A2, W[15],  6);
    G2(&A2, B2, &C2, D2, E2, W[ 0], 14);
    G2(&E2, A2, &B2, C2, D2, W[ 5],  6);
    G2(&D2, E2, &A2, B2, C2, W[12],  9);
    G2(&C2, D2, &E2, A2, B2, W[ 2], 12);
    G2(&B2, C2, &D2, E2, A2, W[13],  9);
    G2(&A2, B2, &C2, D2, E2, W[ 9], 12);
    G2(&E2, A2, &B2, C2, D2, W[ 7],  5);
    G2(&D2, E2, &A2, B2, C2, W[10], 15);
    G2(&C2, D2, &E2, A2, B2, W[14],  8);
    
    /* parallel round 5 */
    F2(&B2, C2, &D2, E2, A2, W[12] ,  8);
    F2(&A2, B2, &C2, D2, E2, W[15] ,  5);
    F2(&E2, A2, &B2, C2, D2, W[10] , 12);
    F2(&D2, E2, &A2, B2, C2, W[ 4] ,  9);
    F2(&C2, D2, &E2, A2, B2, W[ 1] , 12);
    F2(&B2, C2, &D2, E2, A2, W[ 5] ,  5);
    F2(&A2, B2, &C2, D2, E2, W[ 8] , 14);
    F2(&E2, A2, &B2, C2, D2, W[ 7] ,  6);
    F2(&D2, E2, &A2, B2, C2, W[ 6] ,  8);
    F2(&C2, D2, &E2, A2, B2, W[ 2] , 13);
    F2(&B2, C2, &D2, E2, A2, W[13] ,  6);
    F2(&A2, B2, &C2, D2, E2, W[14] ,  5);
    F2(&E2, A2, &B2, C2, D2, W[ 0] , 15);
    F2(&D2, E2, &A2, B2, C2, W[ 3] , 13);
    F2(&C2, D2, &E2, A2, B2, W[ 9] , 11);
    F2(&B2, C2, &D2, E2, A2, W[11] , 11);
    
    /* combine results */
    D2 += C1 + ctx->state[1]; 
    ctx->state[1] = ctx->state[2] + D1 + E2;
    ctx->state[2] = ctx->state[3] + E1 + A2;
    ctx->state[3] = ctx->state[4] + A1 + B2;
    ctx->state[4] = ctx->state[0] + B1 + C2;
    ctx->state[0] = D2;
}

void rmd160_update( rmd160_context *ctx, uint8 *input, uint32 length )
{
    uint32 left, fill;

    if( ! length ) return;
    left = ctx->total[0] & 0x3F;
    fill = 64 - left;
    ctx->total[0] += length;
    ctx->total[0] &= 0xFFFFFFFF;
    if( ctx->total[0] < length ) ctx->total[1]++;
    if( left && length >= fill ) {
        memcpy( (void *) (ctx->buffer + left),
                (void *) input, fill );
        rmd160_process( ctx, (uint32*) ctx->buffer );
        length -= fill;
        input  += fill;
        left = 0;
    }
    while( length >= 64 ) {
        rmd160_process( ctx, (uint32*) input );
        length -= 64;
        input  += 64;
    }
    if( length ) {
        memcpy( (void *) (ctx->buffer + left),
                (void *) input, length );
    }
}

void rmd160_finish( rmd160_context *ctx, uint8 digest[20] )
{
    unsigned int i;
    uint32       X[16];
    uint8* strptr = ctx->buffer;
    memset(X, 0, sizeof(X));
    for (i=0; i<(ctx->total[0]&63); i++) {
       X[i>>2] ^= (uint32) *strptr++ << (8 * (i&3));
    }
    X[(ctx->total[0]>>2)&15] ^= (uint32)1 << (8*(ctx->total[0]&3) + 7);
    if ((ctx->total[0] & 63) > 55) {
       rmd160_process( ctx, X );
       memset(X, 0, sizeof(X));
    }
    X[14] = ctx->total[0] << 3;
    X[15] = (ctx->total[0] >> 29) | (ctx->total[1] << 3);
    rmd160_process( ctx, X );
    for (i = 0; i < 20; i += 4) {
        digest[i]     =  ctx->state[i>>2];
        digest[i + 1] = (ctx->state[i>>2] >>  8);
        digest[i + 2] = (ctx->state[i>>2] >> 16);
        digest[i + 3] = (ctx->state[i>>2] >> 24);
    }
}
