/**
 * request.c -- parser del hello de SOCKS5
 */
#include <stdio.h>
#include <stdlib.h>

#include "HTTPRequest.h"

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
    memset(p->request, 0, sizeof(*(p->request)));
}

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

static enum http_state
method_check(const uint8_t b, struct http_parser* p) {
    if(remaining_is_done(p)){
        if(b == SP){
            remaining_set(p, MAX_URI_LENGTH-1);
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

static enum http_state
uri_check_automata(const uint8_t b, struct http_parser* p);

static enum http_state
uri_check(const uint8_t b, struct http_parser* p) {
    if(remaining_is_done(p))
        return http_error_uri_too_long;
    
    p->request->absolute_uri[p->i] = b;
    p->i++;
   return uri_check_automata(b,p);
}

static enum http_state
uri_check_automata(const uint8_t b, struct http_parser* p) {
    
     switch(p->uri_state) {
        case uri_init:
              p->host_defined = false;
              p->request->dest_port = DEFAULT_HTTP_PORT;
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
                if(p->i_host < MAX_FQDN-1){
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
            fprintf(stderr, "unknown uri_state %d\n", p->uri_state);
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
            return http_done;
        }
        return http_error_unsupported_version;
    }
    if(VERSION_STRING[p->i] == b){
        p->i++;
        return http_version;
    }
   return http_error_unsupported_version;
}

extern enum http_state http_parser_feed (struct http_parser *p, uint8_t b){
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
            p->state = (b == CR)? http_done_lf: http_error_no_end;
            break;
        case http_done_lf:
             p->state = (b == LF)? http_done: http_error_no_end;
            break;
        case http_done:
        case http_error_unsupported_method:
        case http_error_uri_too_long:
        case http_error_invalid_uri:
        case http_error_unsupported_version:
        case http_error_no_end:
            break;
        default:
            fprintf(stderr, "unknown state %d\n", p->state);
            abort();
    }

    return p->state;
}

extern bool 
http_is_done(const enum http_state state, bool *errored) {
    bool ret;
    switch (state) {
        case http_error_unsupported_method:
        case http_error_uri_too_long:
        case http_error_invalid_uri:
        case http_error_unsupported_version:
        case http_error_no_end:
            if (0 != errored) {
                *errored = true;
            }
            /* no break */
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

extern enum http_state
http_consume(buffer *b, struct http_parser *p, bool *errored) {
    enum http_state st = p->state;

    while(buffer_can_read(b)) {
        const uint8_t c = buffer_read(b);
        st = http_parser_feed(p, c);
        if (http_is_done(st, errored)) {
            break;
        }
    }
    return st;
}

extern int
http_marshall(buffer *b, struct http_request * req){
    size_t n;
    uint8_t *buff = buffer_write_ptr(b, &n);
    size_t method_len, uri_len, version_len;
    method_len = strlen(METHOD_STRING[req->method]);
    uri_len = strlen(req->absolute_uri);
    version_len = strlen("HTTP/1.0");
    if(n < method_len+uri_len+version_len+4) {
        return -1;
    }
    strcpy(buff, METHOD_STRING[req->method]);
    buff += method_len;
    buff[0] = SP;
    strcpy(buff+1, req->absolute_uri);
    buff += uri_len;
    buff[0] = SP;
    strcpy(buff+1, "HTTP/1.0");
    buff += version_len;
    buff[0] = CR;
    buff[1] = LF;
    buffer_write_adv(b, method_len+uri_len+version_len+4);
    return method_len+uri_len+version_len+4;
}
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

