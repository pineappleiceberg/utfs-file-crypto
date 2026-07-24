#ifndef TEST_COMMON_H
#define TEST_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>


static int expect_bytes(
const char *name, 
const uint8_t *actual,
const uint8_t  *expected,
size_t length
)
{

size_t i;

for (i=0; i<length; i++){
if (actual[i] != expected[i]) {
printf("%s differes at byte %lu: got 0x%02x expected 0x%02x\n",
name, (unsigned long)i, (unsigned)actual[i],
(unsigned)expected[i]);
return 1;
}
}
return 0;

}

#endif
