#ifndef XCP_H
#define XCP_H


#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XCP_CHACHA20_KEY_SIZE 32U
#define XCP_CHACHA20_NONCE_SIZE 12U
#define XCP_CHACHA20_BLOCK_SIZE 64U


typedef enum {

XCP_OK = 0,
XCP_PARAM_ERROR = 1,
XCP_AUTH_FAILED = 2,
XCP_BUFFER_TOO_SMALL = 3
} xcp_result_t;



uint32_t xcp_load32_le(const uint8_t src[4]);

void xcp_store32_le(uint8_t dest[4], uint32_t value);

uint32_t xcp_rotl32(uint32_t value, unsigned count);


void xcp_chacha20_quarter_round(uint32_t state[16],
                                unsigned a,
                                unsigned b,
                                unsigned c,
                                unsigned d);


static void chacha20_rounds(uint32_t state[16]);

static void chacha20_inital_state(uint32_t state[16], const uint8_t key[XCP_CHACHA20_KEY_SIZE], uint32_t counter, const uint8_t nonce[XCP_CHACHA20_NONCE_SIZE]);

xcp_result_t xcp_chacha20_block(const uint8_t key[XCP_CHACHA20_KEY_SIZE],
                                uint32_t counter,
                                const uint8_t nonce[XCP_CHACHA20_NONCE_SIZE],
                                uint8_t output[XCP_CHACHA20_BLOCK_SIZE]);


xcp_result_t xcp_chacha20_xor(const uint8_t key[XCP_CHACHA20_KEY_SIZE],
                              uint32_t counter,
                              const uint8_t nonce[XCP_CHACHA20_NONCE_SIZE],
                              const uint8_t *input,
                              uint8_t *output,
                              size_t length);
#ifdef __cplusplus
}
#endif


#endif
