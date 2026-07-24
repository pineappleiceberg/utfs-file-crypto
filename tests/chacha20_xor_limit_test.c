#include "xcp.h"
#include "test_common.h"
#include <string.h>


static int test_final_block_is_allowed(void){
uint8_t key[XCP_CHACHA20_KEY_SIZE] = {0};
uint8_t nonce[XCP_CHACHA20_NONCE_SIZE] = {0};
uint8_t input[XCP_CHACHA20_BLOCK_SIZE] = {0};
uint8_t expected[XCP_CHACHA20_BLOCK_SIZE] = {0};
uint8_t actual[XCP_CHACHA20_BLOCK_SIZE] = {0};
int failures = 0;


failures += xcp_chacha20_block(key, UINT32_MAX, nonce, expected) != XCP_OK;
failures += xcp_chacha20_xor(key, UINT32_MAX, nonce, input, actual, sizeof(actual)) != XCP_OK;
failures += expect_bytes("final legal block counter", actual, expected, sizeof(actual));

return failures;

}


static int test_first_wrapping_request_is_rejected(void){


uint8_t key[XCP_CHACHA20_KEY_SIZE] = {0};
uint8_t nonce[XCP_CHACHA20_NONCE_SIZE] = {0};
uint8_t input[XCP_CHACHA20_BLOCK_SIZE + 1u] = {0};
uint8_t output[XCP_CHACHA20_BLOCK_SIZE + 1u];
uint8_t unchanged[XCP_CHACHA20_BLOCK_SIZE + 1u];
int failures = 0;


memset(output, 0xa5, sizeof(output));
memset(unchanged, 0xa5, sizeof(unchanged));

failures += xcp_chacha20_xor(key, UINT32_MAX, nonce, input, output, sizeof(output)) != XCP_COUNTER_EXHAUSTED;
failures += expect_bytes("counter exhaustion case preserves output", output, unchanged, sizeof(output));

return failures;



}




int main(void){

return test_final_block_is_allowed() + test_first_wrapping_request_is_rejected();


}
