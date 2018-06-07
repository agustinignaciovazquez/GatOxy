#ifndef HTTP_RESPONSE_PARSER_
#define HTTP_RESPONSE_PARSER_

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include  <string.h>
#include "buffer.h"
//-------------------------RFC DEFINES TO PARSE --------------------

/* Tokens as defined by rfc 2616. Also lowercases them.
 *        token       = 1*<any CHAR except CTLs or separators>
 *     separators     = "(" | ")" | "<" | ">" | "@"
 *                    | "," | ";" | ":" | "\" | <">
 *                    | "/" | "[" | "]" | "?" | "="
 *                    | "{" | "}" | SP | HT
 */
#define T(v) v
static const uint8_t normal_url_char[32] = {
/*   0 nul    1 soh    2 stx    3 etx    4 eot    5 enq    6 ack    7 bel  */
        0    |   0    |   0    |   0    |   0    |   0    |   0    |   0,
/*   8 bs     9 ht    10 nl    11 vt    12 np    13 cr    14 so    15 si   */
        0    | T(2)   |   0    |   0    | T(16)  |   0    |   0    |   0,
/*  16 dle   17 dc1   18 dc2   19 dc3   20 dc4   21 nak   22 syn   23 etb */
        0    |   0    |   0    |   0    |   0    |   0    |   0    |   0,
/*  24 can   25 em    26 sub   27 esc   28 fs    29 gs    30 rs    31 us  */
        0    |   0    |   0    |   0    |   0    |   0    |   0    |   0,
/*  32 sp    33  !    34  "    35  #    36  $    37  %    38  &    39  '  */
        0    |   2    |   4    |   0    |   16   |   32   |   64   |  128,
/*  40  (    41  )    42  *    43  +    44  ,    45  -    46  .    47  /  */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
/*  48  0    49  1    50  2    51  3    52  4    53  5    54  6    55  7  */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
/*  56  8    57  9    58  :    59  ;    60  <    61  =    62  >    63  ?  */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |   0,
/*  64  @    65  A    66  B    67  C    68  D    69  E    70  F    71  G  */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
/*  72  H    73  I    74  J    75  K    76  L    77  M    78  N    79  O  */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
/*  80  P    81  Q    82  R    83  S    84  T    85  U    86  V    87  W  */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
/*  88  X    89  Y    90  Z    91  [    92  \    93  ]    94  ^    95  _  */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
/*  96  `    97  a    98  b    99  c   100  d   101  e   102  f   103  g  */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
/* 104  h   105  i   106  j   107  k   108  l   109  m   110  n   111  o  */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
/* 112  p   113  q   114  r   115  s   116  t   117  u   118  v   119  w  */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
/* 120  x   121  y   122  z   123  {   124  |   125  }   126  ~   127 del */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |   0, };

static const char tokens[256] = {
/*   0 nul    1 soh    2 stx    3 etx    4 eot    5 enq    6 ack    7 bel  */
        0,       0,       0,       0,       0,       0,       0,       0,
/*   8 bs     9 ht    10 nl    11 vt    12 np    13 cr    14 so    15 si   */
        0,       0,       0,       0,       0,       0,       0,       0,
/*  16 dle   17 dc1   18 dc2   19 dc3   20 dc4   21 nak   22 syn   23 etb */
        0,       0,       0,       0,       0,       0,       0,       0,
/*  24 can   25 em    26 sub   27 esc   28 fs    29 gs    30 rs    31 us  */
        0,       0,       0,       0,       0,       0,       0,       0,
/*  32 sp    33  !    34  "    35  #    36  $    37  %    38  &    39  '  */
        0,      '!',      0,      '#',     '$',     '%',     '&',    '\'',
/*  40  (    41  )    42  *    43  +    44  ,    45  -    46  .    47  /  */
        0,       0,      '*',     '+',      0,      '-',     '.',      0,
/*  48  0    49  1    50  2    51  3    52  4    53  5    54  6    55  7  */
       '0',     '1',     '2',     '3',     '4',     '5',     '6',     '7',
/*  56  8    57  9    58  :    59  ;    60  <    61  =    62  >    63  ?  */
       '8',     '9',      0,       0,       0,       0,       0,       0,
/*  64  @    65  A    66  B    67  C    68  D    69  E    70  F    71  G  */
        0,      'a',     'b',     'c',     'd',     'e',     'f',     'g',
/*  72  H    73  I    74  J    75  K    76  L    77  M    78  N    79  O  */
       'h',     'i',     'j',     'k',     'l',     'm',     'n',     'o',
/*  80  P    81  Q    82  R    83  S    84  T    85  U    86  V    87  W  */
       'p',     'q',     'r',     's',     't',     'u',     'v',     'w',
/*  88  X    89  Y    90  Z    91  [    92  \    93  ]    94  ^    95  _  */
       'x',     'y',     'z',      0,       0,       0,      '^',     '_',
/*  96  `    97  a    98  b    99  c   100  d   101  e   102  f   103  g  */
       '`',     'a',     'b',     'c',     'd',     'e',     'f',     'g',
/* 104  h   105  i   106  j   107  k   108  l   109  m   110  n   111  o  */
       'h',     'i',     'j',     'k',     'l',     'm',     'n',     'o',
/* 112  p   113  q   114  r   115  s   116  t   117  u   118  v   119  w  */
       'p',     'q',     'r',     's',     't',     'u',     'v',     'w',
/* 120  x   121  y   122  z   123  {   124  |   125  }   126  ~   127 del */
       'x',     'y',     'z',      0,      '|',      0,      '~',       0 };
       
#define BIT_AT(a, i)                                                \
  (!!((unsigned int) (a)[(unsigned int) (i) >> 3] &                  \
   (1 << ((unsigned int) (i) & 7))))

#define CR                  '\r'
#define LF                  '\n'
#define ASCII_TO_NUM(c)     (c - '0')
#define LOWER(c)            (unsigned char)(c | 0x20)
#define IS_ALPHA(c)         (LOWER(c) >= 'a' && LOWER(c) <= 'z')
#define IS_NUM(c)           ((c) >= '0' && (c) <= '9')
#define IS_ALPHANUM(c)      (IS_ALPHA(c) || IS_NUM(c))
#define IS_HEX(c)           (IS_NUM(c) || (LOWER(c) >= 'a' && LOWER(c) <= 'f'))
#define IS_MARK(c)          ((c) == '-' || (c) == '_' || (c) == '.' || \
  (c) == '!' || (c) == '~' || (c) == '*' || (c) == '\'' || (c) == '(' || \
  (c) == ')')
#define IS_USERINFO_CHAR(c) (IS_ALPHANUM(c) || IS_MARK(c) || (c) == '%' || \
  (c) == ';' || (c) == '&' || (c) == '=' || (c) == '+' || \
  (c) == '$' || (c) == ',')

#define TOKEN(c)            ((c == ' ') ? ' ' : tokens[(unsigned char)c])

#define IS_URL_CHAR(c)                                                         \
  (BIT_AT(normal_url_char, (unsigned char)c) || ((c) & 0x80))
#define IS_HOST_CHAR(c)                                                        \
  (IS_ALPHANUM(c) || (c) == '.' || (c) == '-' || (c) == '_')
//-------------------------RFC DEFINES TO PARSE --------------------
#define MAX_HEADERS_LENGTH 2000
#define DEFAULT_HTTP_PORT 80
#define SP ' '
/*ENCODING LEN*/
#define GZIP_LEN 5
#define DEFLATE_LEN 8
#define COMPRESS_LEN 9
#define CHUNKED_LEN 8
#define IDENTITY_LEN 9
/*HEADERS LEN*/
#define VERSION_LEN 7
#define CONTENT_LENGTH_LEN 14
#define TRANSFER_ENCODING_LEN 17 
#define CONTENT_TYPE_LEN 12
#define CONTENT_ENCODING_LEN 16
/*TYPES LEN*/
#define TEXT_PLAIN_LEN 10
#define IMG_LEN 5 // IMG/
#define APP_OCTET_LEN 24 // application/octet-stream
#define JPEG_LEN 4
#define PNG_LEN 3
/*PARSER LEN*/
#define STATUS_CODE_LEN 3
#define MAX_REASON_LENGTH 25
#define MAX_ENCODINGS 4 // hacer caso donde tenes mas de 4
#define MAX_ENCODING_LEN 10
#define MAX_CHARSET_LEN 15
#define MAX_TYPES 4
#define MAX_TYPES_LEN 50
/*CHARSET LEN*/
#define CHARSET_LEN 8
#define UTF_LEN 5
#define US_ASCII_LEN 8
#define ISO_LEN 10 

/*ENCODINGS*/
#define IDENTITY 1
#define GZIP 1
#define DEFLATE 2
#define COMPRESS 3
#define CHUNKED 4 

/*CHARSET*/
#define UTF 1
#define US_ASCII 2
#define ISO 3

/*TYPES*/
#define TEXT_PLAIN 1
#define IMG 2
#define JPEG 3
#define PNG 4
#define APP_OCTET 5

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



static const char *HEADER_RES_STRING[] = {
    NULL, "TRANSFER-ENCODING", "CONTENT-LENGTH", "CONTENT-TYPE", "CONTENT-ENCODING"
};

static const char *ENCODING_STRING[] ={
    NULL, "GZIP", "DEFLATE", "COMPRESS", "CHUNKED"
};

//AGREGAR LOS QUE FALTAN
static const char *TYPE_STRING[] = {
    NULL, "TEXT/PLAIN", "IMG/", "IMG/JPEG", "IMG/PNG", "APPLICATION/OCTET-STREAM"
};

static const char *CONTENT_ENCODING_STRING[] = {
    NULL, "IDENTITY"
};

static const char *CHARSET_STRING[] = {
    NULL, "CHARSET"
};

static const char *CHARSET_STRINGS[] = {
    NULL, "UTF-8", "US-ASCII", "ISO-8859-1"
};

static const char * VERSION_STRING = "HTTP/1.";

enum header_res_autom_state {
    header_init,
    header_name,
    header_value,
    header_value_start,
    header_done_cr,
    header_invalid,
    header_done,
    header_transfer_encoding_case,
    header_content_length_case,
    header_content_encoding_case,
    header_content_type_case,
    header_charset_case,
    header_content_encoding_recon,
    header_content_type_recon,
    header_charset_recon,
    header_transfer_encoding_check,
    header_content_type_check,
    header_content_encoding_check,
    header_charset_check,
    header_content_length_consume,
    header_transfer_encoding_consume,
    header_content_length_consume_start,
    header_transfer_encoding_consume_start,
    header_content_encoding_consume_start,
    header_content_type_consume_start,
};

enum http_res_state {
    http_version,
    http_sp,
    http_status_code,
    http_status_reason,
    http_done_cr,
    http_done_cr_cr,
    http_headers_start,
    http_headers,
    http_body_start,
    http_body, 
    http_done,
    http_error_unsupported_encoding,
    http_error_unsupported_code,
    http_error_header_too_long,
    http_error_reason_too_long,
    http_error_unsupported_version,
    http_error_no_end,
    http_error_malformed_response,
};
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
    char headers[MAX_HEADERS_LENGTH];
    uint16_t header_content_length;
    char transfer_encodings[MAX_ENCODING_LEN]; // solo puedo tener un transfer encoding
    char content_encodings[MAX_ENCODING_LEN]; // solo puedo tener un content encoding
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
  struct http_response *response;
  enum http_res_state state;
  enum header_res_autom_state h_state;
  uint16_t i_header;
  uint16_t i_encoding;
  uint16_t i_type; 
  uint16_t i_c_encoding; 
  uint16_t content_length;
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

enum http_response_status {
    status_succeeded                          = 0x00,
    status_general_proxy_server_failure       = 0x01,
    status_connection_not_allowed_by_ruleset  = 0x02,
    status_network_unreachable                = 0x03,
    status_host_unreachable                   = 0x04,
    status_connection_refused                 = 0x05,
    status_ttl_expired                        = 0x06,
    status_command_not_supported              = 0x07,
    status_address_type_not_supported         = 0x08,
};

/** inicializa el parser */
void http_res_parser_init (struct http_res_parser *p);

/** entrega un byte al parser. retorna true si se llego al final  */
enum http_res_state http_res_parser_feed (struct http_res_parser *p, uint8_t b);

/**
 * por cada elemento del buffer llama a `hello_parser_feed' hasta que
 * el parseo se encuentra completo o se requieren mas bytes.
 *
 * @param errored parametro de salida. si es diferente de NULL se deja dicho
 *   si el parsing se debió a una condición de error
 */
enum http_res_state
http_consume(buffer *b, struct http_res_parser *p, bool *errored);

/**
 * Permite distinguir a quien usa hello_parser_feed si debe seguir
 * enviando caracters o no. 
 *
 * En caso de haber terminado permite tambien saber si se debe a un error
 */
bool 
http_is_done(const enum http_res_state state, bool *errored);

/**
 * En caso de que se haya llegado a un estado de error, permite obtener una
 * representación textual que describe el problema
 */
extern const char *
http_error(const struct http_res_parser *p);


/** libera recursos internos del parser */
void http_res_parser_close(struct http_res_parser *p);

/**
 * serializa en buff la una respuesta al hello.
 *
 * Retorna la cantidad de bytes ocupados del buffer o -1 si no había
 * espacio suficiente.
 */
int
http_marshall(buffer *b, struct http_response * res);


/** convierte a errno en socks_response_status */
enum http_response_status errno_to_socks(int e);

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
