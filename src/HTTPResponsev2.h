#ifndef HTTP_RESPONSE_PARSER_
#define HTTP_RESPONSE_PARSER_

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include  <string.h>
#include "buffer.h"
#include "HTTPRequest.h"

//-------------------------RFC DEFINES TO PARSE --------------------
#define MAX_HEADERS_RESPONSE_LENGTH 2000
/*ENCODING LEN*/
#define CHUNKED_LEN 7
#define IDENTITY_LEN 8
/*HEADERS LEN*/
#define CONTENT_LEN 8
#define TRANSFER_ENCODING_LEN 17 
#define CONTENT_TYPE_LEN 12
#define CONTENT_ENCODING_LEN 16

/*PARSER LEN*/
#define STATUS_CODE_LEN 3
#define MAX_REASON_LENGTH 25
#define MAX_ENCODINGS 4 // hacer caso donde tenes mas de 4
#define MAX_ENCODING_LEN 10
#define MAX_CHARSET_LEN 15
#define MAX_TYPES 4
#define MAX_TYPES_LEN 50
#define MAX_CHUNK_LENGTH 7

/*ENCODINGS*/
#define IDENTITY 1
#define GZIP 1
#define DEFLATE 2
#define COMPRESS 3
#define CHUNKED 4 



/*
 *   The client connects to the server, and sends a HTTP Request
 *
 *                 +-------+--------------+------------+
 *                 |METHOD | REQUESTTARGET| HTTP-VER   |
 *                 +-------+--------------+------------+
 *                 |  VAR  | Absolute URI | HTTP/1.0/1 |
 *                 +-------+--------------+------------+
 *
 *  All fields are separated by a SP and always ends with CRLF
 */
/* no es un ADT/CDT para no evitar malloc/free */
/** estado del parser de http request */


enum encoding_type {
    encoding_gzip = 0x01,
    encoding_deflate = 0x02,
    encoding_compress = 0x03,
    encoding_chunked = 0x04,
};

enum chunked_state {
    chunked_number,
    chunked_cr_number,
    chunked_cr_body,
    chunked_body,
    chunked_end_trailer,
    chunked_error,

};

static const char *HEADER_RES_STRING[] = {
    NULL, "TRANSFER-ENCODING", "CONTENT-LENGTH", "CONTENT-TYPE", "CONTENT-ENCODING"
};

static const char *ENCODING_STRING[] ={
    NULL, "GZIP", "DEFLATE", "COMPRESS", "CHUNKED"
};

static const char *CONTENT_ENCODING_STRING[] = {
    NULL, "IDENTITY"
};

static const char * CONTENT_STRING = "CONTENT-";
/* STRUCT HTTP_RESPONSE
    @http_version guarda el caracter de la version despues del punto
    @headers string que guarda todos los header con sus valores
    @header_content_length guarda el valor del header "Content-Length", si no esta presente es -1
    @transfer_encodings guarda el value del header "Transfer-Encoding"
    @content_encodings guarda el value del header "Content-Encoding"
    @content_types array de strings que guarda los distintos valores del header "Content-Type"
    @code_reason guarda la frase que acompana el status code de la respuesta
    @status_code guarda el valor de status_code
*/
struct http_response {
    char http_version; 
    char headers[MAX_HEADERS_RESPONSE_LENGTH];
    uint32_t header_content_length;
    char content_types[MAX_TYPES][MAX_TYPES_LEN]; 
    char code_reason[MAX_REASON_LENGTH];
    int status_code;
};
/* STRUCT HTTP_RES_PARSER
    @response asocia un struct http_response donde se guardan los datos de interes
    @state enum para estados
    @h_state enum para estados dentro del header
    @i_header para avanzar en el parseo del header
    @i_encoding para avanzar en el parseo del value de "Transfer-Encoding"
    @i_type para avanzar en el parseo del value "Content-Type"
    @i_c_encoding para avanzar en el parseo del value de "Content-Encoding"
    @transfer_encodings cantidad de transfer encodings
    @content_encodings cantidad de content encodings
    @content_types cantidad de content types
    @encoding tipo de encoding que se esta parseando
    @type tipo de dato que se esta parseando
    @is_chunked true si se parseo el Transfer-Encoding: chunked
    @is_identity true si no se parseo otro encoding
    @body_found true si hay un body
*/
struct http_res_parser {
  struct buffer * buffer_output;
  struct http_response *response;
  uint16_t index;
  enum http_state state;
  enum header_autom_state h_state;
  enum chunked_state chunked_state;
  uint32_t chunked_remain_num;
  char chunked_remain[MAX_CHUNK_LENGTH];
  uint16_t i_header;
  uint16_t i_encoding;
  uint16_t i_type; 
  uint16_t i_c_encoding; 
  uint32_t content_length;
  uint16_t transfer_encodings; 
  uint16_t content_encodings; 
  uint16_t content_types; 
  uint16_t encoding;
  uint16_t type; 

  bool is_chunked; // add
  bool is_identity; // add
  bool body_found;

   /** cuantos bytes tenemos que leer*/
   uint16_t n;
   /** cuantos bytes ya leimos */
   uint16_t i;
};

/** inicializa el parser */
void http_res_parser_init (struct http_res_parser *p, struct buffer * b);

/** entrega un byte al parser. retorna true si se llego al final  */
enum http_state http_res_parser_feed (struct http_res_parser *p, uint8_t b);

/**
 * por cada elemento del buffer llama a `hello_parser_feed' hasta que
 * el parseo se encuentra completo o se requieren mas bytes.
 *
 * @param errored parametro de salida. si es diferente de NULL se deja dicho
 *   si el parsing se debió a una condición de error
 */
enum http_state
http_res_consume(buffer *b, struct http_res_parser *p, bool *errored);

/**
 * Permite distinguir a quien usa hello_parser_feed si debe seguir
 * enviando caracters o no. 
 *
 * En caso de haber terminado permite tambien saber si se debe a un error
 */
bool 
http_res_is_done(const enum http_state state, bool *errored);

enum chunked_state http_chunked_parser (struct http_res_parser *p, uint8_t b);
/** libera recursos internos del parser */
void http_res_parser_close(struct http_res_parser *p);

/**
 * serializa en buff la una respuesta al hello.
 *
 * Retorna la cantidad de bytes ocupados del buffer o -1 si no había
 * espacio suficiente.
 */
int
http_res_marshall(buffer *b, struct http_response * res, buffer * b2);


/* TEST SUITE */

void test_response_with_content();
void test_response_simple();
void test_invalid_version();
void test_invalid_code_long();
void test_status_too_long();
void test_malformed_response_fails();
void test_response_with_single_transfer();
void test_response_with_multi_transfer();
void test_response_with_content_encoding();
void test_response_with_content_and_transfer();
void test_response_with_content_type_png();
void test_response_with_content_type_jpeg();
void test_response_with_content_type_app();
void test_response_with_content_type_text();
void test_response_with_content_type_text_charset();
void test_response_with_multi_types();
void test_response_with_multi_types_charset();
void test_response_with_multi_type_formats();
#endif
