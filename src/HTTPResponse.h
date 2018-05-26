// Parser Response HEADER 

/* INCLUDES */
#include <stdint.h>
#include <stdbool.h>

#include <netinet/in.h>

#include "buffer.h"

/*
	The SOCKS request information is sent by the client as soon as it has
   established a connection to the SOCKS server, and completed the
   authentication negotiations.  The server evaluates the request, and
   returns a reply formed as follows:

        +----+-----+-------+------+----------+----------+
        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+

     Where:

          o  VER    protocol version: X'05'
          o  REP    Reply field:
             o  X'00' succeeded
             o  X'01' general SOCKS server failure
             o  X'02' connection not allowed by ruleset
             o  X'03' Network unreachable
             o  X'04' Host unreachable
             o  X'05' Connection refused
             o  X'06' TTL expired
             o  X'07' Command not supported
             o  X'08' Address type not supported
             o  X'09' to X'FF' unassigned
          o  RSV    RESERVED
          o  ATYP   address type of following address
             o  IP V4 address: X'01'
             o  DOMAINNAME: X'03'
             o  IP V6 address: X'04'
          o  BND.ADDR       server bound address
          o  BND.PORT       server bound port in network octet order

   Fields marked RESERVED (RSV) must be set to X'00'.

   */


enum socks_res_field {
    socks_res_succeeded					= 0x00,
    socks_res_general_failure      		= 0x01,
    socks_res_connection_not_allowed 	= 0x02,
    socks_res_network_unreachable 		= 0x03,
    socks_res_host_unreachable 			= 0x04,
    socks_res_connection_refused 		= 0x05,
    socks_res_ttl_expired 				= 0x06,
    socks_res_cmd_not_supported 		= 0x07,
    socks_res_atype_not_supported 		= 0x08,
};

/*
enum socks_response_status {
    status_succeeded                          = 0x00,
    status_general_SOCKS_server_failure       = 0x01,
    status_connection_not_allowed_by_ruleset  = 0x02,
    status_network_unreachable                = 0x03,
    status_host_unreachable                   = 0x04,
    status_connection_refused                 = 0x05,
    status_ttl_expired                        = 0x06,
    status_command_not_supported              = 0x07,
    status_address_type_not_supported         = 0x08,
};
*/

enum socks_addr_type {
    socks_res_addrtype_ipv4   = 0x01,
    socks_res_addrtype_domain = 0x03,
    socks_res_addrtype_ipv6   = 0x04,
};

union socks_addr {
    char fqdn[0xff];
    struct sockaddr_in  ipv4;
    struct sockaddr_in6 ipv6;
};

struct response {
    enum  socks_res_field   field;
    enum  socks_addr_type dest_addr_type;
    union socks_addr      dest_addr;
    /** port in network byte order */
    in_port_t             dest_port;
};

enum response_state {
   response_version,
   response_field,
   response_rsv,
   response_atyp,
   response_dstaddr_fqdn,
   response_dstaddr,
   response_dstport,

   // apartir de aca están done
   response_done,

   // y apartir de aca son considerado con error
   response_error,
   response_error_unsupported_version,
   response_error_unsupported_atyp,

};

struct response_parser {
   struct response *response;
   enum response_state state;
   /** cuantos bytes tenemos que leer*/
   uint8_t n;
   /** cuantos bytes ya leimos */
   uint8_t i;
};

/** inicializa el parser */
void 
response_parser_init (struct response_parser *p);

/** entrega un byte al parser. retorna true si se llego al final  */
enum response_state 
response_parser_feed (struct response_parser *p, const uint8_t c);

/**
 * por cada elemento del buffer llama a `response_parser_feed' hasta que
 * el parseo se encuentra completo o se requieren mas bytes.
 *
 * @param errored parametro de salida. si es diferente de NULL se deja dicho
 *   si el parsing se debió a una condición de error
 */
enum response_state
response_consume(buffer *b, struct response_parser *p, bool *errored);

/**
 * Permite distinguir a quien usa socks_hello_parser_feed si debe seguir
 * enviando caracters o no. 
 *
 * En caso de haber terminado permite tambien saber si se debe a un error
 */
bool 
response_is_done(const enum response_state st, bool *errored);

void
response_close(struct response_parser *p);

/**
 * serializa en buff la una respuesta al response.
 *
 * Retorna la cantidad de bytes ocupados del buffer o -1 si no había
 * espacio suficiente.
 */
extern int
response_marshall(buffer *b,
                 const enum socks_res_field status);


/** convierte a errno en socks_response_status */
enum socks_res_field errno_to_socks(int e);

#include <netdb.h>
#include <arpa/inet.h>

/** se encarga de la resolcuión de un response */
enum socks_res_field
cmd_resolve(struct response* response,  struct sockaddr **originaddr,
            socklen_t *originlen, int *domain);

