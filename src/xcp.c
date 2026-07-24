#include "xcp.h"
#include <string.h>








static const uint8_t chacha20_sigma[16] = {
0x65, 0x78, 0x70, 0x61, 
0x6e, 0x64, 0x20, 0x33,
0x32, 0x2d, 0x62, 0x79,
0x74, 0x65, 0x20, 0x6b


};

uint32_t xcp_load32_le(const uint8_t src[4]){


return ((uint32_t)src[0] | ((uint32_t)src[1]<<8) |  ((uint32_t)src[2]<<16) |  ((uint32_t)src[3]<<24));


}


void xcp_store32_le(uint8_t dest[4], uint32_t value){

dest[0] = (uint8_t)(value);
dest[1] = (uint8_t)(value >> 8);
dest[2] = (uint8_t)(value >> 16);
dest[3] = (uint8_t)(value >> 24);
}


uint32_t xcp_rotl32(uint32_t value, unsigned count){

return (uint32_t)((value << count) | (value >> (32u - count)));

}



void xcp_chacha20_quarter_round(uint32_t state[16],
                                unsigned a,
                                unsigned b,
                                unsigned c,
                                unsigned d){

state[a] += state[b];
state[d] ^= state[a];
state[d] = xcp_rotl32(state[d], 16);



state[c] += state[d];
state[b] ^= state[c];
state[b] = xcp_rotl32(state[b], 12);


state[a] += state[b];
state[d] ^= state[a];
state[d] = xcp_rotl32(state[d], 8);


state[c] += state[d];
state[b] ^= state[c];
state[b] = xcp_rotl32(state[b], 7);

}

static void chacha20_rounds(uint32_t state[16]){

unsigned round;


for (round = 0; round < 10u; round++){

  xcp_chacha20_quarter_round(state, 0, 4, 8, 12);
  xcp_chacha20_quarter_round(state, 1, 5, 9, 13);
  xcp_chacha20_quarter_round(state, 2, 6, 10, 14);
  xcp_chacha20_quarter_round(state, 3, 7, 11, 15);
  xcp_chacha20_quarter_round(state, 0, 5, 10, 15);
  xcp_chacha20_quarter_round(state, 1, 6, 11, 12);
  xcp_chacha20_quarter_round(state, 2, 7, 8, 13);
  xcp_chacha20_quarter_round(state, 3, 4, 9, 14);


}


}




static void chacha20_inital_state(uint32_t state[16], const uint8_t key[XCP_CHACHA20_KEY_SIZE], uint32_t counter, const uint8_t nonce[XCP_CHACHA20_NONCE_SIZE]){



unsigned i;



for (i=0; i<4u; i++){

state[i] = xcp_load32_le(&chacha20_sigma[i*4u]);

}


for (i=0; i<8u; i++){

state[4u + i] = xcp_load32_le(&key[i*4u]);


}

state[12] = counter;
state[13] = xcp_load32_le(&nonce[0]);
state[14] = xcp_load32_le(&nonce[4]);
state[15] = xcp_load32_le(&nonce[8]);


}



xcp_result_t xcp_chacha20_block(const uint8_t key[XCP_CHACHA20_KEY_SIZE],
                                uint32_t counter,
                                const uint8_t nonce[XCP_CHACHA20_NONCE_SIZE],
                                uint8_t output[XCP_CHACHA20_BLOCK_SIZE])
{


uint32_t state[16];
uint32_t working[16];
unsigned i;

if (key == NULL || nonce == NULL || output == NULL){

return XCP_PARAM_ERROR;

}

chacha20_inital_state(state, key, counter, nonce);

memcpy(working, state, sizeof(working));

chacha20_rounds(working);

for (i=0; i<16u ; i++) {

xcp_store32_le(&output[i * 4u], working[i]+state[i]);


}

return XCP_OK;

}



xcp_result_t xcp_chacha20_xor(const uint8_t key[XCP_CHACHA20_KEY_SIZE],
                              uint32_t counter, 
                              const uint8_t nonce[XCP_CHACHA20_NONCE_SIZE],
                              const uint8_t *input,
                              uint8_t *output,
                              size_t length){
if(key ==NULL || nonce == NULL || input == NULL || output == NULL){
return XCP_PARAM_ERROR;
}

uint8_t block[XCP_CHACHA20_BLOCK_SIZE];
size_t offset = 0u;

while (offset < length){
size_t i;
const size_t remaining = length - offset;
const size_t take = remaining < XCP_CHACHA20_BLOCK_SIZE
                    ? remaining
                    : XCP_CHACHA20_BLOCK_SIZE;



if (xcp_chacha20_block(key, counter, nonce, block) != XCP_OK) {

return XCP_PARAM_ERROR;
}


counter++;


for (i = 0; i < take; i++){

output[offset + i] = (uint8_t)(input[offset+i] ^ block[i]);

}
offset += take;

}
memset(block, 0 ,sizeof(block));

return XCP_OK;


}
