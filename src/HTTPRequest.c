#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "logging.h"
#include <assert.h>
#include <errno.h>

#include "HTTPRequest.h"

/**
 * HTTPRequest -- parser de requests HTTP
 */

static void
remaining_set(struct http_parser* p, const int n) {

    p->i = 0;
    p->n = n;
}

static int
remaining_is_done(struct http_parser* p) {

    return p->i >= p->n;
}


extern void http_parser_init (struct http_parser *p){

    p->state     = http_method;
    p->uri_state     = uri_init;
    p->request->header_content_length = -1;
    p->host_defined = false;
    p->is_proxy_connection = false;
    p->method_supported =false;
    memset(p->request, 0, sizeof(*(p->request)));
    memset(p->request->headers_raw, 0, MAX_HEADERS_LENGTH_ARRAY);
    strcpy(p->request->headers_raw, PROXY_HEADER);
    p->request->headers = p->request->headers_raw + PROXY_HEADER_LEN;
}

/** reconoce el metodo */
static enum http_state
method_recon(const uint8_t b, struct http_parser* p) {

    if('G' == b) {
        remaining_set(p, GET_LEN);
        p->i = 1;
        p->request->method = http_get_method;
        return http_check_method;
    } else if('P' == b) {
        remaining_set(p, POST_LEN);
        p->i = 1;
        p->request->method = http_post_method;
        return http_check_method;
    } else if('H' == b){
        remaining_set(p, HEAD_LEN);
        p->i = 1;
        p->request->method = http_head_method;
        return http_check_method;
    } 
   return http_error_unsupported_method;
}

/** parsea el metodo utilizado */
static enum http_state
method_check(const uint8_t b, struct http_parser* p) {

    if(remaining_is_done(p)){
        if(b == SP){
            remaining_set(p, MAX_URI_LENGTH - 1);
            p->method_supported =true;
            return http_absolute_uri;
        }
        return http_error_unsupported_method;
    }
    if(METHOD_STRING[p->request->method][p->i] == b){
        p->i++;
        return http_check_method;
    }
   return http_error_unsupported_method;
}

/** maquina de estados para parsear el uri */
static enum http_state
uri_check_automata(const uint8_t b, struct http_parser* p);

/** guarda el uri */
static enum http_state
uri_check(const uint8_t b, struct http_parser* p) {

    if(remaining_is_done(p)){
        return http_error_uri_too_long;
    }
    p->request->absolute_uri[p->i] = b;
    p->i++;
   return uri_check_automata(b,p);
}

static enum http_state
uri_check_automata(const uint8_t b, struct http_parser* p) {
    
     switch(p->uri_state) {
        case uri_init:
              p->host_defined = false;
              p->request->dest_port = htons(DEFAULT_HTTP_PORT);
              p->i_host = 0;
              if (b == '/' || b == '*') {
                 p->uri_state =  uri_path;
              }
              if (IS_ALPHA(b)) {
                p->uri_state = uri_schema;
              }
            break;
        case uri_schema:
            if (!IS_ALPHA(b)) {
                p->uri_state = uri_invalid;
                if(b == ':'){
                    p->uri_state = uri_slash;
                }
            }
            //else do nothing and continue consuming schema chars
            break;
        case uri_slash:
             p->uri_state = uri_invalid;
            if(b == '/'){
                 p->uri_state = uri_slash_slash;
             }
            break;
        case uri_slash_slash:
            p->uri_state = uri_invalid;
            if(b == '/'){
                 p->uri_state = uri_auth;
            }
            break;
        case uri_auth_userinfo:
            if (b == '@') {
                p->uri_state = uri_invalid;
                break;
            }
        case uri_auth_host:
        case uri_auth:
            p->uri_state = uri_invalid;
            if (IS_USERINFO_CHAR(b)) {
                p->host_defined = true;
                if(p->i_host < MAX_FQDN - 1){
                    //defensive programming
                    p->request->fqdn[p->i_host] = b;
                    p->i_host++;
                }
                p->uri_state = uri_auth;
            }
            if (b == '@') {
                p->i_host = 0;
                p->host_defined = false;
                p->uri_state = uri_auth_userinfo;
            }
            if (b == '/') {
                p->request->fqdn[p->i_host] = '\0';
                p->uri_state = uri_path;
            }
            if (b == '?') {
                p->request->fqdn[p->i_host] = '\0';
                p->uri_state = uri_query;
            }
            if(b == ':'){
                p->request->fqdn[p->i_host] = '\0';
                p->request->dest_port = 0;
                p->uri_state = uri_auth_port;
            }
            if(b == '['){
                p->i_host = 0;
                p->host_defined = false;
                p->uri_state = uri_ipv6;
            }
            break;
        case uri_ipv6:
            p->uri_state = uri_invalid;
            if (IS_USERINFO_CHAR(b) || b == ':') {
                p->host_defined = true;
                if(p->i_host < MAX_FQDN-1){
                    //defensive programming
                    p->request->fqdn[p->i_host] = b;
                    p->i_host++;
                }
                p->uri_state = uri_ipv6;
            }
            if(b == ']'){
                p->request->fqdn[p->i_host] = '\0';
                p->uri_state = uri_auth_host;
            }
            break;
        case uri_auth_port:
            p->uri_state = uri_invalid;
            if(IS_NUM(b)){
                p->request->dest_port = (p->request->dest_port)*10 + ASCII_TO_NUM(b);
                p->uri_state = uri_auth_port;
            }
            if (b == '/') {
                p->request->dest_port = htons(p->request->dest_port);
                p->uri_state = uri_path;
            }
            if (b == '?') {
                p->request->dest_port = htons(p->request->dest_port);
                p->uri_state = uri_query;
            }
            break;
        case uri_path:
            p->uri_state = uri_invalid;
            if (IS_URL_CHAR(b)) {
                p->uri_state = uri_path;
            }
            if(b == '?'){
                p->uri_state = uri_query;
            }
            if (b == SP) {
                p->uri_state = uri_done;
            }
            break;
        case uri_query:
            p->uri_state = uri_invalid;
            if (IS_URL_CHAR(b) || b == '?' || b == '#') {
                p->uri_state = uri_query;
            }
            if (b == SP) {
                p->uri_state = uri_done;
            }
            break;
        case uri_done:
        case uri_invalid:
            break;
        default:
            abort();
    }
    if(p->uri_state == uri_done){
        //si uri ya esta verificada pasamos a el estado de version
        remaining_set(p, VERSION_LEN);
        return http_version;
    }
    //si hay un error de uri se pone en el estado del parser, sino se continua verificando
    return (p->uri_state != uri_invalid)? http_absolute_uri:http_error_invalid_uri;
}


static enum http_state
version_check(const uint8_t b, struct http_parser* p) {

    if(remaining_is_done(p)){
        if(b == '1' || b == '0'){
            p->request->http_version = b;
            remaining_set(p, MAX_HEADERS_LENGTH-1); // desde aca en adelante solo usamos el i para chequear el header no pase del limite predefinido por nosotros
            return http_done_cr;
        }
        return http_error_unsupported_version;
    }
    if(VERSION_STRING[p->i] == b){
        p->i++;
        return http_version;
    }
   return http_error_unsupported_version;
}

/** parsea el header Host */
static enum header_autom_state
host_case(const uint8_t b, struct http_parser* p){

    int a = toupper(b);
    p->i_header++;
    if (!IS_URL_CHAR(a) && (a != ':')){
        return header_invalid;
    }else if((p->i_header == HOST_LEN) && (a == ':')){
        return header_host_consume_start;
    }else if(p->i_header == HOST_LEN){
        return header_name;
    }else if(a == HEADER_STRING[1][p->i_header]){
        return header_host_check;
    }  
    return (a == ':') ? header_value_start : header_name;
}

/** header proxy para verificar si el mensaje ya paso por nuestro proxy */
static enum header_autom_state
proxy_header_case(const uint8_t b, struct http_parser* p){

    p->i_header++;
    if(p->i_header == PROXY_HEADER_LEN-1 && b == LF){
        p->is_proxy_connection = true;
        return header_invalid;
    }

    if(PROXY_HEADER[p->i_header] == b && p->i_header < PROXY_HEADER_LEN){
        return header_proxy_check;
    }else if(!IS_URL_CHAR(b) && (b != ':') && (b != SP)){
        return header_invalid;
    }else if(b == ':'){
        return header_value_start;
    }else if(PROXY_HEADER[p->i_header] != b){
        return header_name;
    }
    
    return header_done;
}

/** chequea el valor de content length */
static enum header_autom_state 
content_length_case(const uint8_t b, struct http_parser* p ){

    int a = toupper(b);
    p->i_header++;  
    if (!IS_URL_CHAR(a) && (a != ':')){
        return header_invalid;
    }else if((p->i_header == CONTENT_LENGTH_LEN) && (a == ':')){
        return header_content_length_consume_start;
    } else if(p->i_header == CONTENT_LENGTH_LEN){
        return header_name;
    }else if(a == HEADER_STRING[2][p->i_header]){
        return header_content_length_check;
    }  
    return (a == ':') ? header_value_start : header_name;
}

/** maquina de estados que parsea los headers */
static enum http_state
header_check_automata(const uint8_t b, struct http_parser* p) {
  
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
                p->h_state = header_content_length_check;
                break;
            }
            if(a == 'H'){
                p->i_header = 0;
                p->h_state = header_host_check;
                break;
            }
            if(a == 'A'){
                p->i_header = 0;
                p->h_state = header_proxy_check;
                break;
            }
        case header_name:
            p->h_state = header_invalid;
            if(IS_URL_CHAR(b))
                p->h_state = header_name;
            if(b == ':')
                p->h_state = header_value_start;
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
            if(b == CR)
                p->h_state = header_done_cr;
            break;
        case header_done_cr:
            if(b == LF)
                p->h_state = header_done;
            break;
        case header_proxy_check:
            p->h_state = proxy_header_case(b, p);
            break;
        case header_content_length_check:
            p->h_state = content_length_case(b, p);
            break;
        case header_host_check:
            p->h_state = host_case(b, p);
            break;
        case header_content_length_consume_start:
            if(b == SP){
                p->h_state = header_content_length_consume;
                break;
            }
        case header_content_length_consume:
            p->h_state = header_invalid;
            if(IS_NUM(b)){
                p->request->header_content_length = 
                    (p->request->header_content_length) * 10 + ASCII_TO_NUM(b);
                p->h_state = header_content_length_consume;
            }
            if(b == CR)
                    p->h_state = header_done_cr;
            break;
        case header_host_consume_start:
            p->i_host = 0;
            if(b == SP){
                p->h_state = header_host_consume;
                break;
            }
        case header_host_consume:
            p->h_state = header_invalid;
            if (IS_USERINFO_CHAR(b)) {
                if(p->i_host < MAX_FQDN-1){
                    //defensive programming
                    if (p->host_defined == false){
                        p->request->fqdn[p->i_host] = b;
                        p->i_host++;
                    }
                }
                p->h_state = header_host_consume;
            }
            if(b == ':'){
                if (p->host_defined == false){
                    p->request->dest_port = 0;
                    p->request->fqdn[p->i_host] = '\0';
                }
                p->h_state = header_port_consume;
            }
            if(b == CR){
                if (p->host_defined == false){
                    p->request->fqdn[p->i_host] = '\0';
                }    
                p->h_state = header_done_cr;
            }
            break;
        case header_port_consume:
            p->h_state = header_invalid;
            if(IS_NUM(b)){
                if (p->host_defined == false){
                    p->request->dest_port =
                                (p->request->dest_port)*10 + ASCII_TO_NUM(b);
                }
                p->h_state = header_port_consume;
            }
            if(b == CR){
                if (p->host_defined == false){
                    p->request->dest_port = htons(p->request->dest_port);
                }
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
        //si ya esta el header seguimos buscando
        return http_headers_start;
    }
    //si hay un error de uri se pone en el estado del parser, sino se continua
    //verificando
    return (p->h_state != header_invalid)? http_headers:http_error_malformed_request;
}


/** copia los datos de header al buffer */
static enum http_state
header_check(const uint8_t b, struct http_parser* p) {
    
    if(remaining_is_done(p)){
        return http_error_header_too_long;
    }
    p->request->headers[p->i] = b;
    p->i++;
    return header_check_automata(b,p);
}

/** maquina de estados para flujo de parseo */
extern enum http_state 
http_parser_feed (struct http_parser *p, uint8_t b){

    switch(p->state) {
        case http_method:
            p->state = method_recon(b, p);
            break;
        case http_check_method:
            p->state = method_check(b,p);
            break;
        case http_absolute_uri:
            p->state = uri_check(b,p);
            break;
        case http_version:
            p->state = version_check(b,p);
            break;
        case http_done_cr:
        case http_done_cr_cr:
            p->state = http_error_no_end;
            if(b == CR){
                p->state = http_done_cr_cr;
            }
            if(b == LF){
                p->state = http_headers_start;
            }
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
            p->state = http_error_malformed_request;
            if(b == LF){
                
                p->state = http_body;
            }
            break;
        case http_body:
            p->body_found = true;
            break;
        case http_done:
        case http_error_unsupported_method:
        case http_error_uri_too_long:
        case http_error_invalid_uri:
        case http_error_unsupported_version:
        case http_error_no_end:
        case http_error_header_too_long:
        case http_error_malformed_request:
            break;
        default:
            abort();
    }
    return p->state;
}

/** parsea errores */
extern bool 
http_is_done(const enum http_state state, bool *errored) {

    bool ret;
    switch (state) {
        case http_error_unsupported_method:
        case http_error_uri_too_long:
        case http_error_invalid_uri:
        case http_error_unsupported_version:
        case http_error_malformed_request:
        case http_error_no_end:
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

extern const char *
http_error(const struct http_parser *p) {
    char *ret;
    switch (p->state) {
        //TODO COMPLETE THIS WITH CORRESPONDENT STRINGS
        case http_error_unsupported_method:
        case http_error_uri_too_long:
        case http_error_invalid_uri:
        case http_error_no_end:
        case http_error_unsupported_version:
            ret = "unsupported version";
            break;
        default:
            ret = "";
            break;
    }
    return ret;
}

extern void http_parser_close(struct http_parser *p) {
    /* no hay nada que liberar */
}

/** consumir un caracter del buffer para parsear */
extern enum http_state
http_consume(buffer *b, struct http_parser *p, bool *errored) {

    enum http_state st = p->state;
    /** si ya estamos por leer body no consumimos mas y se lo 
     *  pasamos directamente al origin! */
    while(buffer_can_read(b)) { 
        const uint8_t c = buffer_read(b);
        st = http_parser_feed(p, c);
        if (http_is_done(st, errored)){
            /*if(p->is_proxy_connection){
                strcpy(p->request->fqdn, "google.com"); //TODO fix
            }*/
            break;
        }
    }
    return st;
}

/** serializa informacion importante del parseo */
extern int
http_marshall(buffer *b, struct http_request * req, buffer *b2){

    size_t n;
    uint8_t *buff = buffer_write_ptr(b, &n);
    size_t size_body;
    uint8_t *ptr = buffer_read_ptr(b2, &size_body);
    size_t method_len, uri_len, version_len, headers_len, total_len;
    method_len = strlen(METHOD_STRING[req->method]);
    headers_len = strlen(req->headers_raw);
    uri_len = strlen(req->absolute_uri);
    version_len = strlen(VERSION_STRING);
    total_len = method_len+uri_len+version_len+headers_len+6;
    if(n < total_len+size_body) {
        return -1;
    }
    strcpy(buff, METHOD_STRING[req->method]);
    buff += method_len;
    buff[0] = SP;
    buff++;
    strcpy(buff, req->absolute_uri);
    buff += uri_len;
    strcpy(buff, VERSION_STRING);
    buff += version_len;
    buff[0] = req->http_version;
    buff[1] = CR;
    buff[2] = LF;
    buff += 3;
    strcpy(buff, req->headers_raw);
    buff += headers_len;
    buff[0] = CR;
    buff[1] = LF;
    
    //fixeamos que el body quede despues de los headers
    buffer_write_adv(b, total_len);
    for(int i = 0; i < size_body; i++){
         const uint8_t c = buffer_read(b2);
         buffer_write(b, c);
    }
    return total_len;
}

// TODO borrar
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

//TODO pasar a archivo de tests

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/* TESTS *//*
#define FIXBUF(b, data) buffer_init(&(b), N(data), (data)); \
                        buffer_write_adv(&(b), N(data))

#define N(x) (sizeof(x)/sizeof(x[0]))
void test_get_request_simple();
void test_get_request_with_port();
void test_invalid_method();
void test_invalid_method_long();
void test_invalid_version();
void test_get_method_lower_case_fails();

int main () {
    int n, aux;


    LOG_PRIORITY("Starting new test suit of HTTPRequest.c");
    
    test_invalid_method();
    test_invalid_method_long();
    test_invalid_version();
    test_get_method_lower_case_fails();
    test_get_request_simple();
    test_get_request_with_port();
    
}

void test_invalid_version() {
    LOG_DEBUG("Test invalid version");
    
    
    struct http_request request;
    struct http_parser parser = {
        .request = &request,
    };
    http_parser_init(&parser);
    
    uint8_t data[] = 
    "GET / $%3/1.3\r\n"
    "Host: 127.0.0.1\r\n"
    "\r\n";

    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum http_state st = http_consume(&b, &parser, &errored);

    assert(errored);
    assert(st == http_error_unsupported_version);
    LOG_DEBUG("Test invalid version succesfull");
}

void test_get_method_lower_case_fails() {
    LOG_DEBUG("Test get lower case invalid");
    
    
    struct http_request request;
    struct http_parser parser = {
        .request = &request,
    };
    http_parser_init(&parser);
    
    uint8_t data[] = 
    "get ";

    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum http_state st = http_consume(&b, &parser, &errored);

    assert(errored);
    assert(st == http_error_unsupported_method);
    LOG_DEBUG("Test get lower case invalid succesfull");
}

void test_invalid_method_long() {
    LOG_DEBUG("Test invalid method long");
    
    
    struct http_request request;
    struct http_parser parser = {
        .request = &request,
    };
    http_parser_init(&parser);
    
    uint8_t data[] = 
    "GETTer / HTTP/1.1\r\n"
    "Host: 127.0.0.1\r\n"
    "\r\n";

    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum http_state st = http_consume(&b, &parser, &errored);

    assert(errored);
    assert(st == http_error_unsupported_method);
    LOG_DEBUG("Test invalid method long succesfull");
}

void test_invalid_method() {
    LOG_DEBUG("Test invalid method");
    
    
    struct http_request request;
    struct http_parser parser = {
        .request = &request,
    };
    http_parser_init(&parser);
    
    uint8_t data[] = 
    "HAT / HTTP/1.1\r\n"
    "Host: 127.0.0.1\r\n"
    "\r\n";

    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum http_state st = http_consume(&b, &parser, &errored);

    assert(errored);
    assert(st == http_error_unsupported_method);
    LOG_DEBUG("Test invalid method succesfull");
}

void test_get_request_simple() {
    LOG_DEBUG("Test simple get request");
    
    
    struct http_request request;
    struct http_parser parser = {
        .request = &request,
    };
    http_parser_init(&parser);
    
    uint8_t data[] = 
    "GET / HTTP/1.1\r\n"
    "Host: 127.0.0.1\r\n"
    "\r\n";

    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum http_state st = http_consume(&b, &parser, &errored);
    
    char dst[50];
    sprintf(dst, "Admin Consume::: state end >%d<", st); 
    LOG_DEBUG(dst);

    assert(!errored);
    assert(st == http_done);
    assert(parser.request->method == http_get_method);
    LOG_DEBUG("Test simple get request succesfull");
}

void test_get_request_with_port() {
    LOG_DEBUG("Testing get request with port");
    
    
    struct http_request request;
    struct http_parser parser = {
        .request = &request,
    };
    http_parser_init(&parser);
    
    uint8_t data[] = 
    "GET / HTTP/1.1\r\n"
    "Host: 127.0.0.1:8081\r\n"
    "\r\n";

    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum http_state st = http_consume(&b, &parser, &errored);
    
    char dst[50];
    sprintf(dst, "Admin Consume::: state end >%d<", st); 
    LOG_DEBUG(dst);

    assert(!errored);
    assert(st == http_done);
    assert(parser.request->method == http_get_method);
    assert(strcmp(parser.request->dest_port, "8081")==0);
    LOG_DEBUG("Test get request with port succesfull");
}*/

