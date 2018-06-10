#ifndef BUFFER_SIZE
#define BUFFER_SIZE

#include <limits.h>

#define DEFAULT_BUFFER_SIZE 4*1024*1024
#define HEADERS_BUFFER_SIZE 2000

int
get_buffer_size();

int
get_headers_buffer_size();


int
update_buffer_size(int new_buffer_size);

#endif