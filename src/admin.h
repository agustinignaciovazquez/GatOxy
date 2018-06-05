// TODO emprolijar y ordenar todo pq es un lio

#ifndef ADMIN_H_Ds3wbvgeUHWkGm7B7QLXvXKoxlA
#define ADMIN_H_Ds3wbvgeUHWkGm7B7QLXvXKoxlA

#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"
#include "logging.h"

#include <netinet/in.h>
#include  <string.h>

/*
*   The admin connects to the server, and sends a version
* identifier,a secret passcode, the method to use, and a data field
*
*                 +----+-----------------+----------+--------------+
*                 |VER | SECRET_PASSCODE | METHOD   |    DATA      | //TODO esto de data no lo hice
*                 +----+-----------------+----------+--------------+
*                 | 1  |  1 to MAX_INT   | 1 to 255 | 1 to MAX_INT |
*                 +----+-----------------+----------+--------------+
*
*  The VER field is set to X'01' for this version of the protocol.
*  The SECRET_PASSCODE field contains an int used to auth with the admin passcode(hardcoded in code).
*  The method field contains a char used to switch between all the methods.
*  Client must send an int contained in data field that is used in some methods (like buffer_change_size()),
*  If the method does not require this field (like get_metrics() or get_logs()) it should be set to zero
*/
/** estado del parser de admin request */
enum admin_state {
    admin_version,
    admin_done_field_version, //1 space character between each field, \r\n after data
    admin_secret_pass,
    admin_done_field_password,
    admin_recon_method,
    admin_check_method,
    admin_done_field_method,
    admin_data,
    admin_done_field_data,
    admin_done_request,
    admin_done,
    admin_error_unsupported_version, //11
    admin_error_bad_passcode, //12
    admin_error_bad_method, //13
    admin_error_bad_request,
};

#define ADMIN_METHOD_MAX_LENGTH 19
enum admin_method {
    metrics = 0x01,
    logs = 0x02,
    enable_transformer = 0x03,
    disable_transformer = 0x04
};

#define METRICS_LEN 7
#define LOGS_LEN 4
#define ENABLE_TRANSFORMER_LEN 18
#define DISABLE_TRANSFORMER_LEN 19
#define SP ' '
#define CR '\r'
#define LF '\n'

static const char *ADMIN_METHOD_STRING[] = {
    NULL, "metrics", "logs", "enable_transformer", "disable_transformer"
};

struct admin_request {
    enum  admin_method method;
    char admin_version;
    in_port_t dest_port;
};

struct admin_parser {
    struct admin_request *request;
    enum admin_state state;
    /** cuantos bytes tenemos que leer*/
    uint8_t n;
    /** cuantos bytes ya leimos */
    uint8_t i;
};

#define ADMIN_VERSION_LEN 7
static const char * ADMIN_VERSION_STRING = "ADMIN_V";

#define ADMIN_SECRET_PASS_STRING_LEN 6
static const char * ADMIN_SECRET_PASS_STRING = "admin";

/** inicializa el parser */
void
admin_parser_init (struct admin_parser *p);

/** entrega un byte al parser. retorna true si se llego al final  */
enum admin_state
admin_parser_feed (struct admin_parser *p, uint8_t b);

/**
 * por cada elemento del buffer llama a `hello_parser_feed' hasta que
 * el parseo se encuentra completo o se requieren mas bytes.
 *
 * @param errored parametro de salida. si es diferente de NULL se deja dicho
 *   si el parsing se debió a una condición de error
 */
enum admin_state
admin_consume(buffer *b, struct admin_parser *p, bool *errored);

/**
 * Permite distinguir a quien usa hello_parser_feed si debe seguir
 * enviando caracters o no.
 *
 * En caso de haber terminado permite tambien saber si se debe a un error
 */
bool
admin_is_done(const enum admin_state state, bool *errored);

/**
 * En caso de que se haya llegado a un estado de error, permite obtener una
 * representación textual que describe el problema
 */
extern const char *
admin_error(const struct admin_parser *p);


/** libera recursos internos del parser */
void
admin_parser_close(struct admin_parser *p);

/**
 * serializa en buff la una respuesta al hello.
 *
 * Retorna la cantidad de bytes ocupados del buffer o -1 si no había
 * espacio suficiente.
 */
int
admin_marshall(buffer *b, struct admin_request * req);

#endif