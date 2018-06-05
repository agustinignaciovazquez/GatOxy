/**
 * response.c -- parser del hello de SOCKS5
 */
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "logging.h"
#include <assert.h>

#include "HTTPResponsev2.h"

static void
remaining_set(struct http_res_parser* p, const int n) {
    p->i = 0;
    p->n = n;
}

static int
remaining_is_done(struct http_res_parser* p) {
    return p->i >= p->n;
}

/* TODO : chequear inicializacion */
extern void http_res_parser_init (struct http_res_parser *p){
    p->state     = http_version;
    p->content_length = -1;
    p->transfer_encodings = 0;
    p->charset_flag = false;

    memset(p->response, 0, sizeof(*(p->response)));
    remaining_set(p, VERSION_LEN);
}

static enum http_res_state
status_code(const uint8_t b, struct http_res_parser * p){
    if( remaining_is_done(p) ){
        if ( b == SP ){
            remaining_set(p, MAX_REASON_LENGTH-1);
            return http_status_reason;
        }
        return http_error_unsupported_code;
    }
    if( IS_NUM(b) ){
        p->response->status_code = (p->response->status_code)*10 + ASCII_TO_NUM(b);
        p->i++;
        return http_status_code;
    }
    return http_error_unsupported_code;
}

static enum http_res_state
status_code_reason(const uint8_t b, struct http_res_parser * p){
    if(remaining_is_done(p)){
        if(b==CR){
            remaining_set(p, MAX_HEADERS_LENGTH-1);
            return http_done_cr;
        }
        return http_error_reason_too_long;
    }
    if(IS_URL_CHAR(b)){
        p->response->code_reason[p->i] = b;
        p->i++;
        return http_status_reason;
    }
    if( b==CR ){
        return http_done_cr;
    }
    return http_error_malformed_response;
}

static enum http_res_state
version_check(const uint8_t b, struct http_res_parser* p) {
    if(remaining_is_done(p)){
        if(b == '1' || b == '0'){
            p->response->http_version = b;
            return http_sp;
        }
        return http_error_unsupported_version;
    }
    if(VERSION_STRING[p->i] == b){
        p->i++;
        return http_version;
    }
   return http_error_unsupported_version;
}


/* Chequea si es el header Content-Length, si no, chequea si es Content-Type
    si no, chequea si es Content-Encoding, si no, es un header cualquiera */

static enum header_res_autom_state 
content_length_case(const uint8_t b, struct http_res_parser* p ){

    int a=toupper(b);
    p->i_header++;  
    if (!IS_URL_CHAR(a) && (a!=':')){
        return header_invalid;
    }else if((p->i_header == CONTENT_LENGTH_LEN) && (a==':')){
        return header_content_length_consume_start;
    } else if(p->i_header == CONTENT_LENGTH_LEN){
        return header_name;
    }else if(a == HEADER_RES_STRING[2][p->i_header]){
        return header_content_length_case;
    }else if(a == HEADER_RES_STRING[3][p->i_header]){
        return header_content_type_case;
    }else if(a == HEADER_RES_STRING[4][p->i_header]){
        return header_content_encoding_case;
    }  
    return (a==':') ? header_value_start : header_name;

}

static enum header_res_autom_state 
content_type_case(const uint8_t b, struct http_res_parser* p ){

    int a=toupper(b);
    p->i_header++;  
    if (!IS_URL_CHAR(a) && (a!=':')){
        return header_invalid;
    }else if((p->i_header == CONTENT_TYPE_LEN) && (a==':')){
        return header_content_type_consume_start;
    } else if(p->i_header == CONTENT_TYPE_LEN){
        return header_name;
    }else if(a == HEADER_RES_STRING[3][p->i_header]){
        return header_content_type_case;
    }else if(a == HEADER_RES_STRING[4][p->i_header]){
        return header_content_encoding_case;
    }
    return (a==':') ? header_value_start : header_name;

}

static enum header_res_autom_state 
content_encoding_case(const uint8_t b, struct http_res_parser* p ){

    int a=toupper(b);
    p->i_header++;  
    if (!IS_URL_CHAR(a) && (a!=':')){
        return header_invalid;
    }else if((p->i_header == CONTENT_ENCODING_LEN) && (a==':')){
        return header_content_encoding_consume_start;
    } else if(p->i_header == CONTENT_ENCODING_LEN){
        return header_name;
    }else if(a == HEADER_RES_STRING[4][p->i_header]){
        return header_content_encoding_case;
    }
    return (a==':') ? header_value_start : header_name;

}

static enum header_res_autom_state
transfer_encoding_case(const uint8_t b, struct http_res_parser * p){
    int a = toupper(b);
    p->i_header++;
    if(!IS_URL_CHAR(a) && (a != ':')){
        return header_invalid;
    }else if((p->i_header == TRANSFER_ENCODING_LEN) && (a == ':')){
        return header_transfer_encoding_consume_start;
    }else if(p->i_header == TRANSFER_ENCODING_LEN){
        return header_name;
    }else if(a == HEADER_RES_STRING[1][p->i_header]){
        return header_transfer_encoding_case;
    }
    return (a == ':') ? header_value_start : header_name;
}

/* CHECK FOR TEXT/PLAIN IMAGE/JPEG IMAGE/PNG APPLICATION/OCTET-STREAM*/
/* en TEXT/PLAIN guardar el charset */
/* creo que voy a tener que hacer una funcion aparte para poder parsearlo
    ya que si no no voy a saber como distinguirlo, encima hay que soportar
    mas de un type
*/
/* buscar los otros types */
static enum header_res_autom_state
type_recon(const uint8_t b, struct http_res_parser* p) {
    if( remaining_is_done(p) ){
        if( b == CR ){
            remaining_set(p, MAX_HEADERS_LENGTH-1);
            return header_done_cr;
        }
        //return http_error_unsupported_type;
        return header_invalid;
    }
    if('t' == b) { // TEXT_PLAIN
        p->i_type = 0;
        remaining_set(p, TEXT_PLAIN_LEN); 
        p->type = TEXT_PLAIN; 
        p->i = 1;
        p->response->content_types[p->content_types++][p->i_type++] = b;
        return header_content_type_check; // modify
    } else if('i' == b) {
        /* puede ser JPEG o PNG */
        p->i_type = 0;
        p->type = IMG; 
        remaining_set(p, IMG_LEN); 
        p->i = 1;
        p->response->content_types[p->content_types++][p->i_type++] = b;
        return header_content_type_check;
    } else if('a' == b){ // APP_OCTET_STREAM
        p->i_type = 0;
        remaining_set(p, APP_OCTET_LEN);
        p->type = APP_OCTET; 
        p->i = 1;
        p->response->content_types[p->content_types++][p->i_type++] = b;
        return header_content_type_check;
    } 
    /* si queremos parsear cualquier type: */

    /*
    if( IS_URL_CHAR(b) ){
        return header_content_type_recon;
    }
    */

    return header_invalid; // podriamos definir un estado de invalid type
}

/* Chequeamos si es alguno de los types conocidos */

static enum header_res_autom_state
type_check(const uint8_t b, struct http_res_parser* p) {
    int a=toupper(b);
    p->i_type++;  
    if(remaining_is_done(p)){
        if(a == ';' && p->type == TEXT_PLAIN){
            remaining_set(p, CHARSET_LEN); 
            return header_charset_case;
        }
        if(a == CR){ // solo aceptamos un unico type
            remaining_set(p, MAX_HEADERS_LENGTH-1);
            return header_done_cr;
        }
        if(p->type == IMG){

            if( a == 'J'){
                p->type = JPEG; 
                remaining_set(p, JPEG_LEN); 
                return header_content_type_check; 
            }else if(a == 'P'){
                p->type = PNG;
                remaining_set(p, PNG_LEN);
                return header_content_type_check;
            }
            
        }
        //return http_error_unsupported_encoding;
        return header_invalid;
    }
    if(TYPE_STRING[p->type][p->i_type] == a){
        p->response->content_types[p->content_types][p->i_type++] = b;
        return header_content_type_check;
    }
   //return http_error_unsupported_encoding;
    return header_invalid;
}

/* chequear si es charset */

static enum header_res_autom_state
charset_case(const uint8_t b, struct http_res_parser * p){
    int a = toupper(b);
    p->i_charset_head++; // reuse
    if(!IS_URL_CHAR(a) && (a != '=')){
        return header_invalid;
    }else if((p->i_charset_head == CHARSET_LEN) && (a == '=')){ 
        p->i_charset = 0;
        return header_charset_recon;
    }else if(a == CHARSET_STRING[1][p->i_charset_head++]){
        return header_charset_case; 
    }
    return header_invalid;
}

/*check charset value*/

static enum header_res_autom_state
charset_recon(const uint8_t b, struct http_res_parser* p) {
    if( remaining_is_done(p) ){
        if( b == CR ){
            remaining_set(p, MAX_HEADERS_LENGTH-1);
            return header_done_cr;
        }
        //return http_error_unsupported_type;
        return header_invalid;
    }
    if( p->charset_flag ){ 
        p->charset_flag = 0;
        if( b == 't'){ // UTF
            p->charset = UTF; 
            p->i = 1;
            remaining_set(p, UTF_LEN); 
            p->response->charset[p->i_charset++] = b;
            return header_charset_check;
        }
        if( b == 's'){ // US-ASCII
            p->charset = US_ASCII; 
            p->i = 1;
            remaining_set(p, US_ASCII_LEN);
            p->response->charset[p->i_charset++] = b;
            return header_charset_check;
        }

        return header_invalid;
    }
    if('u' == b) { // UTF-8 o US-ASCII
        p->charset_flag = 1;
        p->i_charset = 0; 
        p->response->charset[p->i_charset++] = b; 
        return header_charset_recon; // modify
    } else if('i' == b) {   //iso-8859-1
        p->i_charset = 0;
        p->charset = ISO; 
        remaining_set(p, ISO_LEN); 
        p->i = 1;
        p->response->charset[p->i_charset++] = b;
        return header_charset_check;
    }
    /* si queremos parsear cualquier charset: */

    /*
    if( IS_URL_CHAR(b) ){
        return header_charset_recon;
    }
    */

    return header_invalid; // podriamos definir un estado de invalid type
}

/* chequear si es alguno de los aceptados*/
static enum header_res_autom_state
charset_check(const uint8_t b, struct http_res_parser* p) {
    int a=toupper(b);
    p->i_charset++; 
    if(remaining_is_done(p)){
        if(a == CR){
            remaining_set(p, MAX_HEADERS_LENGTH-1);
            return header_done_cr;
        }
        //return http_error_unsupported_encoding;
        return header_invalid;
    }
    if(CHARSET_STRING[p->charset][p->i_charset] == a){ 
        p->response->charset[p->i_charset++] = b;
        return header_charset_check;
    }
   //return http_error_unsupported_encoding;
    return header_invalid;
}

/* CHECK FOR IDENTITY */
/* Aceptamos otros encodings o los tiramos ?*/
/* copiamos en encodings mientras sea igual a IDENTITY, si se diferencia reiniciamos el i_c_encoding
    para que lo pise
*/

static enum header_res_autom_state
content_encoding_recon(const uint8_t b, struct http_res_parser* p) {
    if(remaining_is_done(p)){
        if( b == CR){
            remaining_set(p, MAX_HEADERS_LENGTH-1);
            return header_done_cr;
        }
        //return http_error_unsupported_encoding; // o error por header muy largo
        return header_invalid;
    }
    if('i' == b) {
        p->i_c_encoding = 0;
        remaining_set(p, IDENTITY_LEN); 
        p->encoding = IDENTITY; /* quiza podemos usar el mismo */ 
        p->i = 1;
        p->response->content_encodings[p->i_c_encoding++] = b;
        return header_content_encoding_check; // define
    }

    /* si queremos que acepte cualq encoding - pedir que i_encoding = 0*/
    /*
    if('i' == b) {
        remaining_set(p, IDENTITY_LEN); // define
        p->encoding = IDENTITY; // quiza podemos usar el mismo --- define
        p->i = 1;
        p->response->content_encodings[p->content_encodings++][p->i_c_encoding++] = b;
        return header_transfer_encoding_check;
    }else{
        return header_content_encoding_recon;

    }
    */

   //return http_error_unsupported_encoding;
    return header_invalid;
}

/*con esto anotamos los encodings */
static enum header_res_autom_state
content_encoding_check(const uint8_t b, struct http_res_parser* p) {
    int a=toupper(b);
    p->i_c_encoding++;  
    if(remaining_is_done(p)){
        if(a == CR){
            remaining_set(p, MAX_HEADERS_LENGTH-1);
            return header_done_cr;
        }
        return header_invalid;
    }
    if(CONTENT_ENCODING_STRING[1][p->i_c_encoding] == a){
        p->response->content_encodings[p->i_c_encoding++] = b;
        return header_content_encoding_check;
    }
   //return http_error_unsupported_encoding;
    return header_invalid;
}

/* CHECK FOR CHUNKED */
static enum header_res_autom_state
encoding_recon(const uint8_t b, struct http_res_parser* p) {
    if('c' == b){
        p->i_encoding = 0;
        p->encoding = CHUNKED;
        remaining_set(p, CHUNKED_LEN);
        p->i = 1;
        p->response->transfer_encodings[p->transfer_encodings++][p->i_encoding++] = b;
        //rellamar
        return header_transfer_encoding_check;
    }
    //return http_error_unsupported_encoding;
    return header_invalid;
}

/* CHECK FOR CHUNKED */
static enum header_res_autom_state
encoding_check(const uint8_t b, struct http_res_parser* p) {
    int a=toupper(b);
    p->i_encoding++;  
    if(remaining_is_done(p)){
        if(a == CR){
            remaining_set(p, MAX_HEADERS_LENGTH-1);
            return header_done_cr;
        }
        return http_error_unsupported_encoding;
    }
    if(ENCODING_STRING[p->encoding][p->i_encoding] == a){ // podria poner chunked directo
        p->response->transfer_encodings[p->transfer_encodings][p->i_encoding++] = b;
        return header_transfer_encoding_check;
    }
    //return http_error_unsupported_encoding;
    return header_invalid;
}

static enum http_res_state
header_check_automata(const uint8_t b, struct http_res_parser* p) {
  
    int a;
     switch(p->h_state) { 

        case header_init:
          
            a=toupper(b);
            if(b == ':'){
                p->h_state = header_invalid;
                break;
            }
            if(a == 'C'){
                p->i_header = 0;
                p->h_state = header_content_length_case;
                break;
            }
            if(a == 'T'){
                p->i_header = 0;
                p->h_state = header_transfer_encoding_case;
                break;
            }
        case header_name:
            p->h_state = header_invalid;
            if(IS_URL_CHAR(b))
                p->h_state = header_name;
            if(b == ':'){
                p->h_state = header_value_start;
            }
            break;
        case header_value_start:
            if(b == SP){
                p->h_state = header_value;
                break;
            }
        case header_value:
            p->h_state = header_invalid;
            if(b != '\0')
                p->h_state = header_value;
            if(b == CR){
                p->h_state = header_done_cr;
            }
            break;
        case header_done_cr:
        /*ASK: Si al CR no lo sigue LF no es error ?*/
            if(b == LF){
                p->h_state = header_done;
            }
            break;
        case header_content_type_case:
                p->h_state = content_type_case(b,p);
                break;
        case header_content_encoding_case:
                p->h_state = content_encoding_case(b,p);
                break;
        case header_content_encoding_check:
                p->h_state = content_encoding_check(b,p);
                break;
        case header_content_encoding_consume_start:
            if(b == SP){
                p->h_state = header_content_encoding_recon;
                break;
            }
        case header_content_encoding_recon:
                p->h_state = content_encoding_recon(b,p);
                break;
        case header_content_type_consume_start:
            if(b == SP){
                p->h_state = header_content_type_recon;
                break;
            }
        case header_content_type_recon:
                p->h_state = type_recon(b,p);
                break;
        case header_content_type_check:
                p->h_state = type_check(b,p);
                break;
        case header_charset_case:
                p->h_state = charset_case(b,p);
                break;
        case header_charset_recon:
                p->h_state = charset_recon(b,p);
                break;
        case header_charset_check:
                p->h_state = charset_check(b,p);
                break;
        case header_content_length_case:
                p->h_state = content_length_case(b, p);
            break;
        case header_transfer_encoding_case:
                p->h_state = transfer_encoding_case(b, p);
            break;
        case header_transfer_encoding_consume_start:
            if(b == SP){
                p->h_state = header_transfer_encoding_consume;
                break;
            }
        case header_transfer_encoding_consume:
            p->h_state = encoding_recon(b, p);
            break;
        case header_transfer_encoding_check:
            p->h_state = encoding_check(b,p);
            break;
        case header_content_length_consume_start:
        /*ASK: si no hay espacio, no deberia dar error?*/
            if(b == SP){
                p->h_state = header_content_length_consume;
                break;
            }
        case header_content_length_consume:
            p->h_state = header_invalid;
            if(IS_NUM(b)){
                p->response->header_content_length = (p->response->header_content_length)*10 + ASCII_TO_NUM(b);
                p->h_state = header_content_length_consume;
            }
            if(b == CR){
                p->h_state = header_done_cr;
            }
            break;
        case header_done:
        case header_invalid:
            break;
        default:
            //fprintf(stderr, "unknown uri_state %d\n", p->uri_state);
            abort(); // legal, seguro y gratuito
    }
    if(p->h_state == header_done){
        //si ya esta el header seguimos buscando
        return http_headers_start;
    }
    //si hay un error de uri se pone en el estado del parser, sino se continua verificando
    return (p->h_state != header_invalid)? http_headers:http_error_malformed_response;
}



static enum http_res_state
header_check(const uint8_t b, struct http_res_parser* p) {
    
    if(remaining_is_done(p)){
        return http_error_header_too_long;
    }
    
    p->response->headers[p->i] = b;
    p->i++;
    return header_check_automata(b,p);
}

/*TODO: change flow */
extern enum http_res_state http_res_parser_feed (struct http_res_parser *p, uint8_t b){
    switch(p->state) {
        /*FIRST*/
        case http_version:
        //fprintf(stderr, "http_version consumo %c",b);
            p->state = version_check(b,p);
            break;
        case http_sp:
            if(b != SP){
                p->state = http_error_malformed_response;
                break;
            }
            remaining_set(p, STATUS_CODE_LEN);
            p->state = http_status_code;
            break;
        case http_status_code:
            p->state = status_code(b,p);
            break;
        case http_status_reason:
            p->state = status_code_reason(b,p);
            break;
        case http_done_cr:
          /*  p->state = http_error_no_end;
            if(b == CR)
                p->state = http_done_cr_cr;
            break;*/
        case http_done_cr_cr:
        //fprintf(stderr, "http_done_cr_cr consumo %c",b);
            p->state = http_error_no_end;
            if(b == CR)
                p->state = http_done_cr_cr;
            if(b == LF)
                p->state = http_headers_start;
            break;
        case http_headers_start:
        //fprintf(stderr, "http_headers_start consumo %d",b);
            p->h_state = header_init;
            remaining_set(p, MAX_HEADERS_LENGTH-1);
            if(b == CR){
                p->state = http_body_start;
                break;
            }
        case http_headers:
        //fprintf(stderr, "http_headers consumo %d",b);
            p->state = header_check(b,p);
            break;
        case http_body_start:
        //fprintf(stderr, "http_body_start consumo %d",b);
            p->state = http_error_malformed_response;
            if(b == LF){
                p->body_found = true;
                p->state = http_done;
            }
            break;
        /* TO BE IMPLEMENTED */
        case http_body:
        //fprintf(stderr, "http_body consumo %d",b);
            //p->state = body_check(b,p);
            p->state = http_done; /*TEMP*/
            break;
        case http_done:
        //fprintf(stderr, "http_done consumo %d",b);
        case http_error_unsupported_encoding:
        case http_error_unsupported_code:
        case http_error_header_too_long:
        case http_error_reason_too_long:
        case http_error_unsupported_version:
        case http_error_no_end:
        case http_error_malformed_response:
            break;
        default:
            //fprintf(stderr, "unknown state %d\n", p->state);
            abort();
    }

    return p->state;
}

extern bool 
http_is_done(const enum http_res_state state, bool *errored) {
    bool ret;
    switch (state) {
        case http_error_unsupported_encoding:
        case http_error_unsupported_code:
        case http_error_header_too_long:
        case http_error_reason_too_long:
        case http_error_unsupported_version:
        case http_error_no_end:
        case http_error_malformed_response:
            if (0 != errored) {
                *errored = true;
            }
            /* no break */
        case http_body:
        case http_done:
            ret = true;
            break;
        default:
            ret = false;
            break;
    }

   return ret;
}

/* TODO complete */
extern const char *
http_error(const struct http_res_parser *p) {
    char *ret;
    switch (p->state) {
        //TODO COMPLETE THIS WITH CORRESPONDENT STRINGS
        case http_error_unsupported_encoding:
        case http_error_unsupported_code:
        case http_error_header_too_long:
        case http_error_reason_too_long:
        case http_error_unsupported_version:
        case http_error_no_end:
        case http_error_malformed_response:
            ret = "unsupported version";
            break;
        default:
            ret = "";
            break;
    }
    return ret;
}

extern void http_res_parser_close(struct http_res_parser *p) {
    /* no hay nada que liberar */
}

extern enum http_res_state
http_consume(buffer *b, struct http_res_parser *p, bool *errored) {
    enum http_res_state st = p->state;

    while(buffer_can_read(b)) { // si ya estamos por leer body no consumimos mas y se lo pasamos directamente al origin!
        const uint8_t c = buffer_read(b);
        st = http_res_parser_feed(p, c);
        if (http_is_done(st, errored) || p->body_found == true){
            break;
        }
    }
    return st;
}

// /*TODO update*/
// extern int
// http_marshall(buffer *b, struct http_response * req){
//     size_t n;
//     uint8_t *buff = buffer_write_ptr(b, &n);
//     size_t method_len, uri_len, version_len;
//     method_len = strlen(METHOD_STRING[req->method]);
//     uri_len = strlen(req->absolute_uri);
//     version_len = strlen("HTTP/1.0");
//     if(n < method_len+uri_len+version_len+4) {
//         return -1;
//     }
//     strcpy(buff, METHOD_STRING[req->method]);
//     buff += method_len;
//     buff[0] = SP;
//     strcpy(buff+1, req->absolute_uri);
//     buff += uri_len;
//     buff[0] = SP;
//     strcpy(buff+1, "HTTP/1.0");
//     buff += version_len;
//     buff[0] = CR;
//     buff[1] = LF;
//     buffer_write_adv(b, method_len+uri_len+version_len+4);
//     return method_len+uri_len+version_len+4;
// }

#include <errno.h>

enum http_response_status
errno_to_socks(const int e) {
    enum http_response_status ret = status_general_proxy_server_failure;
    switch (e) {
        case 0:
            ret = status_succeeded;
            break;
        case ECONNREFUSED:
            ret = status_connection_refused;
            break;
        case EHOSTUNREACH:
            ret = status_host_unreachable;
            break;
        case ENETUNREACH:
            ret = status_network_unreachable;
            break;
        case ETIMEDOUT:
            ret = status_ttl_expired;
            break;
    }
    return ret;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/* TESTS */
#define FIXBUF(b, data) buffer_init(&(b), N(data), (data)); \
                        buffer_write_adv(&(b), N(data))

#define N(x) (sizeof(x)/sizeof(x[0]))
void test_get_response_simple();
void test_get_response_with_port();
void test_invalid_method();
void test_invalid_method_long();
void test_invalid_version();
void test_get_method_lower_case_fails();

int main () {
    int n, aux;


    LOG_PRIORITY("Starting new test suit of HTTPResponsev2.c");
    
    test_invalid_version();
    test_malformed_response_fails();
    test_invalid_code_long();
    test_status_too_long();
    test_response_simple();
    test_response_with_content();
    test_response_with_single_transfer();
    test_response_with_multi_transfer();
    test_response_with_content_and_transfer();

}

void test_invalid_version() {
    LOG_DEBUG("Test invalid version");
    
    
    struct http_response response;
    struct http_res_parser parser = {
        .response = &response,
    };
    http_res_parser_init(&parser);
    
    uint8_t data[] = 
    "HTTP/1.3 400 Bad Request\r\n"
    "Host: 127.0.0.1\r\n"
    "\r\n";

    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum http_res_state st = http_consume(&b, &parser, &errored);

    assert(errored);
    assert(st == http_error_unsupported_version);
    LOG_DEBUG("Test invalid version succesful");
    printf("INVALID VERSION OK\n");
}

void test_malformed_response_fails() {
    LOG_DEBUG("Test malformed response invalid");
    
    
    struct http_response response;
    struct http_res_parser parser = {
        .response = &response,
    };
    http_res_parser_init(&parser);
    
    uint8_t data[] = 
    "abc ";

    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum http_res_state st = http_consume(&b, &parser, &errored);

    assert(errored);
    assert(st == http_error_unsupported_version);
    LOG_DEBUG("Test malformed response succesful");
    printf("MALFORMED RESPONSE OK\n");
}

void test_invalid_code_long() {
    LOG_DEBUG("Test invalid code long");
    
    
    struct http_response response;
    struct http_res_parser parser = {
        .response = &response,
    };
    http_res_parser_init(&parser);
    
    uint8_t data[] = 
    "HTTP/1.1 5555 Fictional\r\n"
    "Host: 127.0.0.1\r\n"
    "\r\n";

    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum http_res_state st = http_consume(&b, &parser, &errored);
    assert(errored);
    assert(st == http_error_unsupported_code);
    LOG_DEBUG("Test invalid code long succesfull");
    printf("STATUS CODE LONG OK\n");
}

void test_status_too_long() {
    LOG_DEBUG("Test status too long");
    
    
    struct http_response response;
    struct http_res_parser parser = {
        .response = &response,
    };
    http_res_parser_init(&parser);
    
    uint8_t data[] = 
    "HTTP/1.1 404 dddddddddddddddddddddddddddddd\r\n"
    "Host: 127.0.0.1\r\n"
    "\r\n";

    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum http_res_state st = http_consume(&b, &parser, &errored);

    assert(errored);
    assert(st == http_error_reason_too_long);
    LOG_DEBUG("Test status reason too long succesful");
    printf("STATUS REASON LONG OK\n");
}

void test_response_simple() {
    LOG_DEBUG("Test simple response");
    
    
    struct http_response response;
    struct http_res_parser parser = {
        .response = &response,
    };
    http_res_parser_init(&parser);
    
    uint8_t data[] = 
    "HTTP/1.1 100 OK\r\n"
    "Host: 127.0.0.1\r\n"
    "\r\n";

    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum http_res_state st = http_consume(&b, &parser, &errored);
    
    /*ASK*/
    char dst[50];
    sprintf(dst, "Admin Consume::: state end >%d<", st); 
    LOG_DEBUG(dst);

    assert(!errored);
    assert(st == http_done);
    LOG_DEBUG("Test simple response succesfull");
    printf("RESPONSE SIMPLE OK\n");
}

void test_response_with_content() {
    LOG_DEBUG("Testing response with content");
    
    
    struct http_response response;
    struct http_res_parser parser = {
        .response = &response,
    };
    http_res_parser_init(&parser);
    
    uint8_t data[] = 
    "HTTP/1.1 100 OK\r\n"
    "Content-Length: 10\r\n"
    "\r\n";

    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum http_res_state st = http_consume(&b, &parser, &errored);

    
    char dst[50];
    sprintf(dst, "Admin Consume::: state end >%d<", st); 
    LOG_DEBUG(dst);

    assert(!errored);
    assert(st == http_done);
    assert(parser.response->header_content_length == ((uint16_t) 10));
    LOG_DEBUG("Test response with content succesfull");
    printf("RESPONSE CONTENT OK\n");
}

void test_response_with_single_transfer() {
    LOG_DEBUG("Testing response with single transfer");
    
    
    struct http_response response;
    struct http_res_parser parser = {
        .response = &response,
    };
    http_res_parser_init(&parser);
    
    uint8_t data[] = 
    "HTTP/1.1 100 OK\r\n"
    "Transfer-Encoding: gzip\r\n"
    "\r\n";

    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum http_res_state st = http_consume(&b, &parser, &errored);

    
    char dst[50];
    sprintf(dst, "Admin Consume::: state end >%d<", st); 
    LOG_DEBUG(dst);

    assert(!errored);
    assert(st == http_done);
    assert(parser.response->transfer_encodings[parser.transfer_encodings-1] == (encoding_gzip));
    LOG_DEBUG("Test response with single transfer succesful");
    printf("RESPONSE SINGLE TRANSFER OK\n");
}

void test_response_with_multi_transfer() {
    LOG_DEBUG("Testing response with content");
    
    
    struct http_response response;
    struct http_res_parser parser = {
        .response = &response,
    };
    http_res_parser_init(&parser);
    
    uint8_t data[] = 
    "HTTP/1.1 100 OK\r\n"
    "Transfer-Encoding: gzip, deflate\r\n"
    "\r\n";

    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum http_res_state st = http_consume(&b, &parser, &errored);

    
    char dst[50];
    sprintf(dst, "Admin Consume::: state end >%d<", st); 
    LOG_DEBUG(dst);

    assert(!errored);
    assert(st == http_done);
    assert(parser.response->transfer_encodings[parser.transfer_encodings-2] == (encoding_gzip));
    assert(parser.response->transfer_encodings[parser.transfer_encodings-1] == (encoding_deflate));
    LOG_DEBUG("Test response with multi transfer succesful");
    printf("RESPONSE MULTI TRANSFER OK\n");
}

void test_response_with_content_and_transfer() {
    LOG_DEBUG("Testing response with content and transfer");
    
    
    struct http_response response;
    struct http_res_parser parser = {
        .response = &response,
    };
    http_res_parser_init(&parser);
    
    uint8_t data[] = 
    "HTTP/1.1 100 OK\r\n"
    "Content-Length: 10\r\n"
    "Transfer-Encoding: gzip\r\n"
    "\r\n";

    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum http_res_state st = http_consume(&b, &parser, &errored);

    
    char dst[50];
    sprintf(dst, "Admin Consume::: state end >%d<", st); 
    LOG_DEBUG(dst);

    assert(!errored);
    assert(st == http_done);
    assert(parser.response->header_content_length == ((uint16_t) 10));
    assert(parser.response->transfer_encodings[parser.transfer_encodings-1] == (encoding_gzip));
    LOG_DEBUG("Test response with content and transfer succesfull");
    printf("RESPONSE CONTENT AND TRANSFER OK\n");
}
