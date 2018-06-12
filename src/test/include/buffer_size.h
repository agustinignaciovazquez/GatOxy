#ifndef BUFFER_SIZE
#define BUFFER_SIZE

#include <limits.h>

#define DEFAULT_BUFFER_SIZE 4*1024*1024
#define HEADERS_BUFFER_SIZE DEFAULT_BUFFER_SIZE

/**
 * devuelve el tamano default del buffer
 */
int
get_buffer_size();

/**
 * devuelve el tamano default del buffer para headers
 */
int
get_headers_buffer_size();


/**
 * permite cambiar el tamano default de los buffers
 */
int
update_buffer_size(int new_buffer_size);

#endif