#include "xcp.h"
#include "test_common.h"

#include <string.h>

static void fill_bytes(uint8_t *buffer, size_t length){

size_t i;

for (i=0u; i < length; i++){

buffer[i] = (uint8_t)(0x20u + i);


}

}



static int test_zero_length_allows_null_data(void){
uint8_t key[XCP_CHACHA20_KEY_SIZE] = {0};
uint8_t nonce[XCP_CHACHA20_NONCE_SIZE] = {0};

return xcp_chacha20_xor(key, 7u, nonce, NULL, NULL, 0u) != XCP_OK;

}

static int test_round_trip_at_block_edges(void){

const size_t lengths[] = {1u, 63u, 64u, 65u};


uint8_t key[XCP_CHACHA20_KEY_SIZE] = {0};
uint8_t nonce[XCP_CHACHA20_NONCE_SIZE] = {0};
uint8_t plaintext[65];
uint8_t ciphertext[65];
uint8_t recovered[65];
size_t i;
int failures = 0;

fill_bytes(plaintext, sizeof(plaintext));


for (i=0u; i<sizeof(lengths) / sizeof(lengths[0]); i++){
const size_t length = lengths[i];

failures += xcp_chacha20_xor(key, 7u, nonce, plaintext, ciphertext, length) != XCP_OK;

failures += xcp_chacha20_xor(key, 7u, nonce, ciphertext, recovered, length) != XCP_OK;


failures += expect_bytes("block-edge round trip test", recovered, plaintext, length);

}

return failures;

}




static int test_exact_in_place_round_trip(void){

uint8_t key[XCP_CHACHA20_KEY_SIZE] = {0};
uint8_t nonce[XCP_CHACHA20_NONCE_SIZE] = {0};
uint8_t original[65];
uint8_t buffer[65];
int failures = 0;


fill_bytes(original, sizeof(original));

memcpy(buffer, original, sizeof(buffer));

failures += xcp_chacha20_xor(key, 7u, nonce, buffer, buffer, sizeof(buffer)) != XCP_OK;

failures += xcp_chacha20_xor(key, 7u, nonce, buffer, buffer, sizeof(buffer)) != XCP_OK;

failures += expect_bytes("exact in place round trip", buffer, original, sizeof(buffer));

return failures;

}



static int test_invalid_parameters_preserve_output(void){

uint8_t key[XCP_CHACHA20_KEY_SIZE] = {0};
uint8_t nonce[XCP_CHACHA20_NONCE_SIZE] = {0};

uint8_t input[1] = {0};
uint8_t output[1];
uint8_t unchanged[1];

int failures = 0;


memset(output, 0xa5, sizeof(output));
memset(unchanged, 0xa5, sizeof(unchanged));

failures += xcp_chacha20_xor(NULL, 7u, nonce, input, output, sizeof(input)) != XCP_PARAM_ERROR;
failures += expect_bytes("null key output preservation", output, unchanged, sizeof(output));

memset(output, 0xa5, sizeof(output));

failures += xcp_chacha20_xor(key, 7u, nonce, NULL, output, sizeof(output)) != XCP_PARAM_ERROR;
failures += expect_bytes("null input output preservation", output, unchanged, sizeof(output));

memset(output, 0xa5, sizeof(output));

failures += xcp_chacha20_xor(key, 7u, NULL, input, output, sizeof(output)) != XCP_PARAM_ERROR;
failures += expect_bytes("null nonce output preservation", output, unchanged, sizeof(output));

memset(output, 0xa5, sizeof(output));


failures += xcp_chacha20_xor(key, 7u, nonce, input, NULL, sizeof(output)) != XCP_PARAM_ERROR;
failures += expect_bytes("null output output preservation", output, unchanged, sizeof(output));

return failures;

}


int main(void){

return test_zero_length_allows_null_data() 
+ test_round_trip_at_block_edges() 
+ test_exact_in_place_round_trip()
+ test_invalid_parameters_preserve_output();


}
