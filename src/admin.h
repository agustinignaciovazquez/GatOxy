#ifndef ADMIN_H_Ds3wbvgeUHWkGm7B7QLXvXKoxlA
#define ADMIN_H_Ds3wbvgeUHWkGm7B7QLXvXKoxlA

#include <stdint.h>
#include <stdbool.h>

#include "buffer.h"

/*
 *   The admin connects to the server, and sends a version
 * identifier,a secret passcode, the method to use, and a data field
 *
 *                 +----+-----------------+----------+--------------+
 *                 |VER | SECRET_PASSCODE | METHOD   |    DATA      |
 *                 +----+-----------------+----------+--------------+
 *                 | 1  |  1 to MAX_INT   | 1 to 255 | 1 to MAX_INT |
 *                 +----+-----------------+----------+--------------+
 *
 *  The VER field is set to X'01' for this version of the protocol.
 *  The SECRET_PASSCODE field contains an int used to auth with the admin passcode(hardcoded in code),
 *  the method field contains a char used to switch between all the methods. 
 *  Client must send an int contained in data field that is used in some methods (like buffer_change_size()),
 *  if the method does not require this field (like get_metrics() or get_logs()) it should be set to zero
 */
/** estado del parser de admin request */

enum admin_state {
    admin_version,
    admin_secret_pass,
    admin_method,
    admin_data,
    admin_done,
    admin_error_unsupported_version,
    admin_error_bad_passcode,
    admin_error_bad_method,
};

enum admin_methods{
    get_metrics,
    get_logs,
    change_buffer_size,
    enable_body_tranformation_function,
}

#endif
