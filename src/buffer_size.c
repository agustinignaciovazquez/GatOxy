/**
 * buffer_size.c -- nos permite manejar los tamanos de los buffers
 */
#include "buffer_size.h"

static int
buffer_size = DEFAULT_BUFFER_SIZE;

static int
headers_buffer_size = HEADERS_BUFFER_SIZE;

int
get_buffer_size(){
    return buffer_size;
}

int
update_buffer_size(int new_buffer_size){
    if(new_buffer_size <= 10 || new_buffer_size > INT_MAX)
    {
        return -1;
    }
    buffer_size = new_buffer_size;
    return 0;
}

int
get_headers_buffer_size(){
    return headers_buffer_size;
}