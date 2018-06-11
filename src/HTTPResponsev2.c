/**
 * HTTPResponsev2.c -- Parser para responses
 */
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "logging.h"
#include <assert.h>
#include <string.h> //strcmp

#include "HTTPResponsev2.h"

/*
 * nos permite establecer el largo maximo del proximo miembro a parsear
 */
static void
remaining_set(struct http_res_parser* p, const int n) {

    p->i = 0;
    p->n = n;
}

/*
 * indica si terminamos de parsear el miembro actual
 */
static int
remaining_is_done(struct http_res_parser* p) {

    return p->i >= p->n;
}

/*
 * inicializa la estructura para el parser
 */
extern void 
http_res_parser_init (struct http_res_parser *p, struct buffer * b){

    p->chunked_state        = chunked_number;
    p->index                = 0;
    p->chunked_remain_num   = 0;
    p->chunked_total_num    = 0;
    p->buffer_output        = b;
    p->body_found           = 0;
    p->state                = http_version;
    p->content_length       = -1;
    p->transfer_encodings   = 0;
    p->is_chunked           = false;
    p->is_identity          = true; // default

    memset(p->response, 0, sizeof(*(p->response)));
    // primer miembro a parsear
    remaining_set(p, VERSION_LEN);
}

/*
 * parsea el codigo de estado de la respuesta
 */
static enum http_state
status_code(const uint8_t b, struct http_res_parser * p){

    if(remaining_is_done(p)){
        if ( b == SP ){
            remaining_set(p, MAX_REASON_LENGTH-1);
            return http_status_reason;
        }
        return http_error_unsupported_code;
    }
    if(IS_NUM(b)){
        p->response->status_code = (p->response->status_code)*10 + 
            ASCII_TO_NUM(b);
        p->i++;
        return http_status_code;
    }
    return http_error_unsupported_code;
}

/*
 * parsea la razon del codigo de estado
 */
static enum http_state
status_code_reason(const uint8_t b, struct http_res_parser * p){

    if(remaining_is_done(p)){
        if( b == CR ){
            remaining_set(p, MAX_HEADERS_RESPONSE_LENGTH-1);
            return http_done_cr;
        }
        return http_error_reason_too_long;
    }
    if(IS_URL_CHAR(b) || b == SP){
        p->response->code_reason[p->i] = b;
        p->i++;
        return http_status_reason;
    }
    if(b == CR){
        remaining_set(p, MAX_HEADERS_RESPONSE_LENGTH-1);
        return http_done_cr;
    }
    return http_error_malformed_response;
}

/*
 * chequea la version de HTTP
 */
static enum http_state
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


/*
 * chequea si es alguno de los headers que comienza con "Content"
 */
static enum header_autom_state 
content_case(const uint8_t b, struct http_res_parser* p ){

    int a = toupper(b);
    p->i_header++;
    if (!IS_URL_CHAR(a) && (a != ':')){
        return header_invalid;
    }else if(p->i_header == CONTENT_LEN){
        if(a == 'L')
            return header_content_length_case;
        if(a == 'T')
            return header_content_type_case;
        if(a == 'E')
            return header_content_encoding_case;
        if(a == ':')
            return header_value_start;
        return header_name;
    }else if(a == CONTENT_STRING[p->i_header]){
        return header_content_case;
    }  
    return (a == ':') ? header_value_start : header_name;

}

/*
 * chequea si el header es "Content-Length"
 */
static enum header_autom_state 
content_length_case(const uint8_t b, struct http_res_parser* p ){

    int a = toupper(b);
    p->i_header++;
    if (!IS_URL_CHAR(a) && (a != ':')){
        return header_invalid;
    }else if((p->i_header == CONTENT_LENGTH_LEN) && (a == ':')){
        return header_content_length_consume_start;
    }else if(p->i_header == CONTENT_LENGTH_LEN){
        return header_name;
    }else if(a == HEADER_RES_STRING[2][p->i_header]){
        return header_content_length_case;
    }  
    return (a == ':') ? header_value_start : header_name;

}

/*
 * chequea si el header es "Content-Type"
 */
static enum header_autom_state 
content_type_case(const uint8_t b, struct http_res_parser* p ){

    int a = toupper(b);
    p->i_header++;
    if (!IS_URL_CHAR(a) && (a != ':')){
        return header_invalid;
    }else if((p->i_header == CONTENT_TYPE_LEN) && (a == ':')){
        return header_content_type_consume_start;
    }else if(p->i_header == CONTENT_TYPE_LEN){
        return header_name;
    }else if(a == HEADER_RES_STRING[3][p->i_header]){
        return header_content_type_case;
    }  
    return (a == ':') ? header_value_start : header_name;

}

/*
 * chequea si el header es "Content-Encoding"
 */
static enum header_autom_state 
content_encoding_case(const uint8_t b, struct http_res_parser* p ){

    int a = toupper(b);
    p->i_header++;  
    if (!IS_URL_CHAR(a) && (a != ':')){
        return header_invalid;
    }else if((p->i_header == CONTENT_ENCODING_LEN) && (a == ':')){
        return header_content_encoding_consume_start;
    } else if(p->i_header == CONTENT_ENCODING_LEN){
        return header_name;
    }else if(a == HEADER_RES_STRING[4][p->i_header]){
        return header_content_encoding_case;
    }
    return (a == ':') ? header_value_start : header_name;

}

/*
 * chequea si el header es "Transfer-Encoding"
 */
static enum header_autom_state
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

/*
 * parseamos los media-types en Content-Type. Estos se guardan en un array
 * de strings para poder parsearlos posteriormente.
 */
static enum header_autom_state
type_recon(const uint8_t b, struct http_res_parser* p) {

    if(b == CR)
        return header_done_cr;
    if('/' == b){
        p->response->content_types[p->content_types][p->i_type] = b;
        return header_content_type_check;
    } else if ( IS_URL_CHAR(b) ){
        p->response->content_types[p->content_types][p->i_type++] = b;
        return header_content_type_recon;
    }

    return header_invalid; 
    // TODO podriamos definir un estado de invalid type
}

/*
 * chequea si hay mas types por parsear y guarda lo parseado despues de la
 * ocurrencia de '/'
 */
static enum header_autom_state
type_check(const uint8_t b, struct http_res_parser* p) {
    
    int a = toupper(b);
    p->i_type++;  
    if(a == CR){
        p->response->content_types[p->content_types][p->i_type] = 0;
        return header_done_cr;
    }else if(a == ',' || a == ';'){ 
        p->response->content_types[p->content_types][p->i_type] = 0;
        p->content_types++;
        if(p->content_types >= MAX_TYPES)
            return header_invalid;
        return header_content_type_consume_start;
    }else if(IS_URL_CHAR(a) || a == '-' || a == '*'){
        p->response->content_types[p->content_types][p->i_type] = b;
        return header_content_type_check;
    }
    return header_invalid;
    // TODO poner error unsupported_type
}

/*
 * chequea los valores para "Content-Encoding". Pregunta particularmente por
 * identity.
 */
static enum header_autom_state
content_encoding_recon(const uint8_t b, struct http_res_parser* p) {
    
    int a = toupper(b);
    if(!IS_URL_CHAR(a) && (a != CR)){
        return header_invalid;
    }else if((p->i_header == IDENTITY_LEN) && (a == CR)){
        p->i_header++;
        p->is_identity = true;
        return header_done_cr;
    }else if(p->i_header == IDENTITY_LEN){
        p->i_header++;
        return header_value;
    }else if(a == CONTENT_ENCODING_STRING[1][p->i_header]){
        p->i_header++;
        return header_content_encoding_recon;
    }
    return (a == CR) ? header_done_cr : header_value;
}

/*
 * chequea los valores de "Transfer-Encoding". Busca particularmente por el
 * valor chunked.
 */
static enum header_autom_state
encoding_recon(const uint8_t b, struct http_res_parser* p) {

    int a = toupper(b);
    if(!IS_URL_CHAR(a) && (a != CR)){
        return header_invalid;
    }else if((p->i_header == CHUNKED_LEN) && (a == CR)){
        p->i_header++;
        p->is_chunked = true;
        return header_done_cr;
    }else if(p->i_header == CHUNKED_LEN){
        p->i_header++;
        return header_value;
    }else if(a == ENCODING_STRING[4][p->i_header]){
        p->i_header++;
        return header_transfer_encoding_consume;
    }
    return (a == CR) ? header_done_cr : header_value;
}

/*
 * maquina de estados que maneja el flujo para el parseo de headers y sus
 * values
 */
static enum http_state
header_check_automata(const uint8_t b, struct http_res_parser* p) {
  
    int a;
    switch(p->h_state) { 

        case header_init:
            a = toupper(b);
            if(b == ':'){
                p->h_state = header_invalid;
                break;
            }
            if(a == 'C'){
                p->i_header = 0;
                p->h_state = header_content_case;
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
            if(b == LF){
                p->h_state = header_done;
            }
            break;
        case header_content_case:
            p->h_state = content_case(b,p);
            break;
        case header_content_type_case:
            p->h_state = content_type_case(b,p);
            break;
        case header_content_encoding_case:
            p->h_state = content_encoding_case(b,p);
            break;
        case header_content_encoding_consume_start:
            p->i_header = 0;
            if(b == SP){
                p->h_state = header_content_encoding_recon;
                break;
            }
        case header_content_encoding_recon:
            p->is_identity = false;
            p->h_state = content_encoding_recon(b,p);
            break;
        case header_content_type_consume_start:
            p->i_type = 0;
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
        case header_content_length_case:
            p->h_state = content_length_case(b, p);
            break;
        case header_transfer_encoding_case:
            p->h_state = transfer_encoding_case(b, p);
            break;
        case header_transfer_encoding_consume_start:
            p->i_header = 0;
            if(b == SP){
                p->h_state = header_transfer_encoding_consume;
                break;
            }
        case header_transfer_encoding_consume:
            p->h_state = encoding_recon(b, p);
            break;
        case header_content_length_consume_start:
            if(b == SP){
                p->h_state = header_content_length_consume;
                break;
            }
        case header_content_length_consume:
            p->h_state = header_invalid;
            if(IS_NUM(b)){
                p->response->header_content_length = 
                    (p->response->header_content_length)*10 + ASCII_TO_NUM(b);
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
            abort();
    }
    if(p->h_state == header_done){
        return http_headers_start;
    }
    return (p->h_state != header_invalid)? http_headers:http_error_malformed_response;
}

/*
 * agrega el caracter al buffer para parsear headers y parsea el header
 */
static enum http_state
header_check(const uint8_t b, struct http_res_parser* p) {
    
    if(remaining_is_done(p)){
        return http_error_header_too_long;
    }
    
    p->response->headers[p->i] = b;
    p->i++;
    return header_check_automata(b,p);
}

/*TODO: change flow */
/*
 * maquina de estados que maneja el flujo del parseo 
 */
extern enum http_state http_res_parser_feed (struct http_res_parser *p, 
                                                uint8_t b){

    switch(p->state) {
        case http_version:
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
        case http_done_cr_cr:
            p->state = http_error_no_end;
            if(b == CR)
                p->state = http_done_cr_cr;
            if(b == LF)
                p->state = http_headers_start;
            break;
        case http_headers_start:
            p->h_state = header_init;
            if(b == CR){
                p->state = http_body_start;
                break;
            }
        case http_headers:
            p->state = header_check(b,p);
            break;
        case http_body_start:
            p->state = http_error_malformed_response;
            if(b == LF){
                p->body_found = true;
                p->state = http_done;
            }
            break;
        case http_body:
            p->state = http_done;
            break;
        case http_done:
        case http_error_unsupported_encoding:
        case http_error_unsupported_code:
        case http_error_header_too_long:
        case http_error_reason_too_long:
        case http_error_unsupported_version:
        case http_error_no_end:
        case http_error_malformed_response:
            break;
        default:
            abort();
    }
    return p->state;
}

/*
 * parsea un mensaje con encoding = chunked
 */
/*TODO terminar de limpiar cuando este listo*/
enum chunked_state http_chunked_parser (struct http_res_parser *p, uint8_t b){

    switch(p->chunked_state) {
        case chunked_number:
        fprintf(stderr, "chunk number\n" );
            p->chunked_state = chunked_error;
            b = toupper(b);
            if( IS_NUM(b) || b=='A' || b=='B' || b=='C'|| b=='D'|| b=='E'||
                     b=='F' ){
                if (p->index == MAX_CHUNK_LENGTH - 1){
                        p->chunked_state = chunked_error;
                }
                p->chunked_remain[p->index] = b;
                p->index++;
                fprintf(stderr, "VALUE%d\n",p->chunked_remain_num  );
                p->chunked_state = chunked_number;
            }
            if (b == CR){
                p->chunked_remain[p->index] = '\0';
                p->chunked_remain_num =  (int)strtol(p->chunked_remain, NULL, 16);
                p->chunked_total_num += p->chunked_remain_num;
                p->chunked_state = chunked_cr_number;
            }
        break; 
        case chunked_cr_number:
        fprintf(stderr, "chunk cr number\n" );
            p->chunked_state = chunked_error;
            if (b == LF){
                p->chunked_state = chunked_body;
                if(p->chunked_remain_num == 0)
                    p->chunked_state = chunked_end_trailer;
            }
        break;

        case chunked_body:

        fprintf(stderr, "chunk body\n" );
            
            fprintf(stderr, "VALUE%d\n",p->chunked_remain_num  );
            p->chunked_state = chunked_body;
            if(p->chunked_remain_num <= 0){
                p->chunked_state = chunked_error;
            }
            if(b == CR && p->chunked_remain_num == 0){
                    p->chunked_state = chunked_cr_body;
            }
            
            p->chunked_remain_num--;
        break;

        case chunked_cr_body:
        fprintf(stderr, "chunk cr body\n" );
            p->chunked_state = chunked_error;
            if (b == LF){
                p->index = 0;
                p->chunked_remain_num = 0;
                p->chunked_state = chunked_number;
            }
        break;
        case chunked_end_trailer:
        fprintf(stderr, "chunk end trailer\n" );
        break;
        case chunked_error:
        fprintf(stderr, "chunk error\n" );
        break;
        default:
            //ffprintf(stderr, stderr, "unknown state %d\n", p->state);
            //abort();
        break;
    }

    return p->chunked_state;
}

/*
 * maneja los errores posibles a la hora de parsear
 */
extern bool 
http_res_is_done(const enum http_state state, bool *errored) {

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

/*
 * por si se necesita podriamos liberar memoria del parser que ya no usaremos
 */
extern void http_res_parser_close(struct http_res_parser *p) {
    /* no hay nada que liberar */
}

/*
 * consume un caracter del buffer
 */
/*TODO limpiar cuando se termine de usar*/
extern enum http_state
http_res_consume(buffer *b, struct http_res_parser *p, bool *errored) {

    enum http_state st = p->state;
    while(buffer_can_read(b)) {
        const uint8_t c = buffer_read(b);
        buffer_write(p->buffer_output , c);
        fprintf(stderr, "CONSUMO %c\n", c);
        st = http_res_parser_feed(p, c);
        if (http_is_done(st, errored) || p->body_found == true){
            fprintf(stderr, "CONTENT LENGTH = %d \n", 
                    p->response->header_content_length);
            fprintf(stderr, "IDENTITY = %d\n", p->is_identity);
            fprintf(stderr, "CHUNKED = %d\n", p->is_chunked);
            fprintf(stderr, "M TYPE 1 = %s \n", 
                    p->response->content_types[0]);
            fprintf(stderr, "M TYPE 2 = %s \n",  
                    p->response->content_types[1]);
            break;
        }
    }
    return st;
}

/*
 * guarda los datos importantes del parser para usar en el proxy
 */
extern int
http_res_marshall(buffer *b, struct http_response * res, buffer * b2){

    size_t n, size_body, version_len, headers_len, total_len, code_reason_len;
    uint8_t *buff = buffer_write_ptr(b, &n);
    uint8_t *ptr = buffer_read_ptr(b, &size_body);
    headers_len = strlen(res->headers);
    version_len = strlen(VERSION_STRING);
    code_reason_len = strlen(res->code_reason);
    total_len = version_len+headers_len + STATUS_CODE_LEN + code_reason_len 
                    + 7;
 

    if(n < total_len) {
        return -1;
    }

    strcpy(buff, VERSION_STRING);
    buff += version_len;
    buff[0] = res->http_version;
    buff[1] = SP;   
    buff += 2;
    sprintf(buff, "%d", res->status_code); // TODO limpar?
    buff += STATUS_CODE_LEN;
    buff[0] = SP;
    buff++;
    strcpy(buff, res->code_reason);
    buff += code_reason_len;
    buff[0] = CR;
    buff[1] = LF;
    buff += 2;
    strcpy(buff, res->headers);
    buff += headers_len;
    buff[0] = CR;
    buff[1] = LF;
    buff += 2;

    
    //fixeamos que el body quede despues de los headers
    buffer_write_adv(b, total_len);
    for(int i = 0; i < size_body; i++){
         const uint8_t c = buffer_read(b);
         buffer_write(b, c);
    }
    return total_len;
}

/* TODO pasar a response_test.c */
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/* TESTS */
/*#define FIXBUF(b, data) buffer_init(&(b), N(data), (data)); \
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
    /* no se pq no funciona, el gdb lo corre bien*//*
    test_response_with_content_encoding();
    test_response_with_content_and_transfer();
    test_response_with_content_type_png();
    test_response_with_content_type_jpeg();
    test_response_with_content_type_app();
    test_response_with_content_type_text();
    test_response_with_content_type_text_charset();
    test_response_with_multi_types();
    test_response_with_multi_types_charset();
    test_response_with_multi_type_formats();

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
    enum http_state st = http_res_consume(&b, &parser, &errored);

    assert(errored);
    assert(st == http_error_unsupported_version);
    LOG_DEBUG("Test invalid version succesful");
    fprintf(stderr, "INVALID VERSION OK\n");
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
    enum http_state st = http_res_consume(&b, &parser, &errored);

    assert(errored);
    assert(st == http_error_unsupported_version);
    LOG_DEBUG("Test malformed response succesful");
    fprintf(stderr, "MALFORMED RESPONSE OK\n");
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
    enum http_state st = http_res_consume(&b, &parser, &errored);
    assert(errored);
    assert(st == http_error_unsupported_code);
    LOG_DEBUG("Test invalid code long succesfull");
    fprintf(stderr, "STATUS CODE LONG OK\n");
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
    enum http_state st = http_res_consume(&b, &parser, &errored);

    assert(errored);
    assert(st == http_error_reason_too_long);
    LOG_DEBUG("Test status reason too long succesful");
    fprintf(stderr, "STATUS REASON LONG OK\n");
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
    enum http_state st = http_res_consume(&b, &parser, &errored);
    
    /*ASK*//*
    char dst[50];
    sfprintf(stderr, dst, "Admin Consume::: state end >%d<", st); 
    LOG_DEBUG(dst);

    assert(!errored);
    assert(st == http_done);
    LOG_DEBUG("Test simple response succesfull");
    fprintf(stderr, "RESPONSE SIMPLE OK\n");
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
    enum http_state st = http_res_consume(&b, &parser, &errored);

    
    char dst[50];
    sfprintf(stderr, dst, "Admin Consume::: state end >%d<", st); 
    LOG_DEBUG(dst);

    assert(!errored);
    assert(st == http_done);
    assert(parser.response->header_content_length == ((uint16_t) 10));
    LOG_DEBUG("Test response with content succesfull");
    fprintf(stderr, "RESPONSE CONTENT OK\n");
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
    "Transfer-Encoding: chunked\r\n"
    "\r\n";

    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum http_state st = http_res_consume(&b, &parser, &errored);

    
    char dst[50];
    sfprintf(stderr, dst, "Admin Consume::: state end >%d<", st); 
    LOG_DEBUG(dst);

    assert(!errored);
    assert(st == http_done);
    assert(parser.is_chunked == true);
    assert( !strcmp( parser.response->transfer_encodings , "chunked") );
    LOG_DEBUG("Test response with single transfer succesful");
    fprintf(stderr, "RESPONSE SINGLE TRANSFER OK\n");
}

/* SOLO PARSEA CHUNKED */
/*
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
    enum http_state st = http_res_consume(&b, &parser, &errored);

    
    char dst[50];
    sfprintf(stderr, dst, "Admin Consume::: state end >%d<", st); 
    LOG_DEBUG(dst);

    assert(!errored);
    assert(st == http_done);
    assert(parser.response->transfer_encodings[parser.transfer_encodings-2] == (encoding_gzip));
    assert(parser.response->transfer_encodings[parser.transfer_encodings-1] == (encoding_deflate));
    LOG_DEBUG("Test response with multi transfer succesful");
    fprintf(stderr, "RESPONSE MULTI TRANSFER OK\n");
}
*//*

void test_response_with_content_encoding() {
    LOG_DEBUG("Testing response with content encoding");
    
    
    struct http_response response;
    struct http_res_parser parser = {
        .response = &response,
    };
    http_res_parser_init(&parser);
    
    uint8_t data[] = 
    "HTTP/1.1 100 OK\r\n"
    "Content-Encoding: identity\r\n"
    "\r\n";

    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum http_state st = http_res_consume(&b, &parser, &errored);

    
    char dst[50];
    sfprintf(stderr, dst, "Admin Consume::: state end >%d<", st); 
    LOG_DEBUG(dst);

    assert(!errored);
    assert(st == http_done);
    assert(parser.is_identity == true);
    assert( !strcmp( parser.response->content_encodings , "identity") );
    LOG_DEBUG("Test response with content encoding succesful");
    fprintf(stderr, "RESPONSE CONTENT ENCODING OK\n");
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
    "Transfer-Encoding: chunked\r\n"
    "\r\n";

    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum http_state st = http_res_consume(&b, &parser, &errored);

    
    char dst[50];
    sfprintf(stderr, dst, "Admin Consume::: state end >%d<", st); 
    LOG_DEBUG(dst);

    assert(!errored);
    assert(st == http_done);
    assert(parser.response->header_content_length == ((uint16_t) 10));
    assert( !strcmp( parser.response->transfer_encodings , "chunked") );
    LOG_DEBUG("Test response with content and transfer succesfull");
    fprintf(stderr, "RESPONSE CONTENT AND TRANSFER OK\n");
}

void test_response_with_content_type_png() {
    LOG_DEBUG("Testing response with content type png");
    
    
    struct http_response response;
    struct http_res_parser parser = {
        .response = &response,
    };
    http_res_parser_init(&parser);
    
    uint8_t data[] = 
    "HTTP/1.1 100 OK\r\n"
    "Content-Type: img/png\r\n"
    "\r\n";

    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum http_state st = http_res_consume(&b, &parser, &errored);

    
    char dst[50];
    sfprintf(stderr, dst, "Admin Consume::: state end >%d<", st); 
    LOG_DEBUG(dst);

    assert(!errored);
    assert(st == http_done);
    assert(!strcmp( parser.response->content_types[parser.content_types] , "img/png"));
    LOG_DEBUG("Test response with content type png");
    fprintf(stderr, "RESPONSE CONTENT TYPE PNG OK\n");
}

void test_response_with_content_type_jpeg() {
    LOG_DEBUG("Testing response with content type jpeg");
    
    
    struct http_response response;
    struct http_res_parser parser = {
        .response = &response,
    };
    http_res_parser_init(&parser);
    
    uint8_t data[] = 
    "HTTP/1.1 100 OK\r\n"
    "Content-Type: img/jpeg\r\n"
    "\r\n";

    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum http_state st = http_res_consume(&b, &parser, &errored);

    
    char dst[50];
    sfprintf(stderr, dst, "Admin Consume::: state end >%d<", st); 
    LOG_DEBUG(dst);

    assert(!errored);
    assert(st == http_done);
    assert( !strcmp( parser.response->content_types[parser.content_types],"img/jpeg") );
    LOG_DEBUG("Test response with content type jpeg");
    fprintf(stderr, "RESPONSE CONTENT TYPE JPEG OK\n");
}

void test_response_with_content_type_app() {
    LOG_DEBUG("Testing response with content type app");
    
    
    struct http_response response;
    struct http_res_parser parser = {
        .response = &response,
    };
    http_res_parser_init(&parser);
    
    uint8_t data[] = 
    "HTTP/1.1 100 OK\r\n"
    "Content-Type: application/octet-stream\r\n"
    "\r\n";

    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum http_state st = http_res_consume(&b, &parser, &errored);

    
    char dst[50];
    sfprintf(stderr, dst, "Admin Consume::: state end >%d<", st); 
    LOG_DEBUG(dst);

    assert(!errored);
    assert(st == http_done);
    assert( !strcmp( parser.response->content_types[parser.content_types],"application/octet-stream") );
    LOG_DEBUG("Test response with content type app");
    fprintf(stderr, "RESPONSE CONTENT TYPE APP OK\n");
}

void test_response_with_content_type_text() {
    LOG_DEBUG("Testing response with content type text");
    
    
    struct http_response response;
    struct http_res_parser parser = {
        .response = &response,
    };
    http_res_parser_init(&parser);
    
    uint8_t data[] = 
    "HTTP/1.1 100 OK\r\n"
    "Content-Type: text/plain\r\n"
    "\r\n";

    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum http_state st = http_res_consume(&b, &parser, &errored);

    
    char dst[50];
    sfprintf(stderr, dst, "Admin Consume::: state end >%d<", st); 
    LOG_DEBUG(dst);

    assert(!errored);
    assert(st == http_done);
    assert( !strcmp( parser.response->content_types[parser.content_types],"text/plain") );
    LOG_DEBUG("Test response with content type text succesful");
    fprintf(stderr, "RESPONSE CONTENT TYPE TEXT OK\n");
}

void test_response_with_content_type_text_charset() {
    LOG_DEBUG("Testing response with content type text charset");
    
    
    struct http_response response;
    struct http_res_parser parser = {
        .response = &response,
    };
    http_res_parser_init(&parser);
    
    uint8_t data[] = 
    "HTTP/1.1 100 OK\r\n"
    "Content-Type: text/plain;charset=UTF-8\r\n"
    "\r\n";

    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum http_state st = http_res_consume(&b, &parser, &errored);

    
    char dst[50];
    sfprintf(stderr, dst, "Admin Consume::: state end >%d<", st); 
    LOG_DEBUG(dst);

    assert(!errored);
    assert(st == http_done);
    assert( !strcmp( parser.response->content_types[parser.content_types],"text/plain;charset=UTF-8") );
    LOG_DEBUG("Test response with content type text charset succesfull");
    fprintf(stderr, "RESPONSE CONTENT TYPE TEXT CHARSET OK\n");
}

void test_response_with_multi_types() {
    LOG_DEBUG("Testing response with multi type");
    
    
    struct http_response response;
    struct http_res_parser parser = {
        .response = &response,
    };
    http_res_parser_init(&parser);
    
    uint8_t data[] = 
    "HTTP/1.1 100 OK\r\n"
    "Content-Type: text/plain, img/png\r\n"
    "\r\n";

    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum http_state st = http_res_consume(&b, &parser, &errored);

    
    char dst[50];
    sfprintf(stderr, dst, "Admin Consume::: state end >%d<", st); 
    LOG_DEBUG(dst);

    assert(!errored);
    assert(st == http_done);
    assert( !strcmp( parser.response->content_types[parser.content_types-1],"text/plain") );
    assert( !strcmp( parser.response->content_types[parser.content_types],"img/png") );
    LOG_DEBUG("Test response with multi types");
    fprintf(stderr, "RESPONSE MULTI TYPES OK\n");
}

void test_response_with_multi_types_charset() {
    LOG_DEBUG("Testing response with multi type charset");
    
    
    struct http_response response;
    struct http_res_parser parser = {
        .response = &response,
    };
    http_res_parser_init(&parser);
    
    uint8_t data[] = 
    "HTTP/1.1 100 OK\r\n"
    "Content-Type: tExT/pLaIn;cHaRsEt=UTF-8, ImG/JpEg\r\n"
    "\r\n";

    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum http_state st = http_res_consume(&b, &parser, &errored);

    
    char dst[50];
    sfprintf(stderr, dst, "Admin Consume::: state end >%d<", st); 
    LOG_DEBUG(dst);

    assert(!errored);
    assert(st == http_done);
    assert( !strcmp( parser.response->content_types[parser.content_types-1],"tExT/pLaIn;cHaRsEt=UTF-8") );
    assert( !strcmp( parser.response->content_types[parser.content_types],"ImG/JpEg") );
    LOG_DEBUG("Test response with multi type charset succesfull");
    fprintf(stderr, "RESPONSE MULTI TYPE CHARSET OK\n");
}

void test_response_with_multi_type_formats() {
    LOG_DEBUG("Testing response with multi type formats");
    
    
    struct http_response response;
    struct http_res_parser parser = {
        .response = &response,
    };
    http_res_parser_init(&parser);
    
    uint8_t data[] = 
    "HTTP/1.1 100 OK\r\n"
    "Content-Type: text/*;q=0.8, application/json;q=0.3\r\n"
    "\r\n";

    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum http_state st = http_res_consume(&b, &parser, &errored);

    
    char dst[50];
    sfprintf(stderr, dst, "Admin Consume::: state end >%d<", st); 
    LOG_DEBUG(dst);

    assert(!errored);
    assert(st == http_done);
    assert( !strcmp( parser.response->content_types[parser.content_types-1],"text/*;q=0.8") );
    assert( !strcmp( parser.response->content_types[parser.content_types],"application/json;q=0.3") );
    LOG_DEBUG("Test response with multi type formats succesfull");
    fprintf(stderr, "RESPONSE MULTI TYPES FORMAT OK\n");
}*/

//////////////////////////////////////////////////////////////////////////////
/////////////// COMBINE HEADER TEST //////////////////////////////////////////



/*

void test_response_multi_headers(){

    struct http_response response;
    struct http_res_parser parser = {
        .response = &response,
    };
    http_res_parser_init(&parser);
    
    uint8_t data[] = 
    "HTTP/1.1 200 OK\r\n"
    "Server: nginx/1.10.3 (Ubuntu)\r\n"
    "Date: Thu, 07 Jun 2018 23:44:40 GMT\r\n"
    "Content-Type: text/html\r\n"
    "Content-Length: 38855\r\n"
    "Last-Modified: Sun, 29 Apr 2018 18:31:39 GMT\r\n"
    "Connection: keep-alive\r\n"
    "ETag: \"5ae60f8b-97c7\"\r\n"
    "Accept-Ranges: bytes\r\n"
    "\r\n";

    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum http_state st = http_res_consume(&b, &parser, &errored);

    assert(errored);
    assert(st == http_error_unsupported_version);
    fprintf(stderr, "NO TE ANDA EL PARSER\n");

}*/
