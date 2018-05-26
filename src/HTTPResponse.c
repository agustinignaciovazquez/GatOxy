// Parser para responses

#include "HTTPResponse.h"

#include <string.h> // memset
#include <arpa/inet.h>

/*testing*/
#include <stdio.h>

static void
remaining_set(struct response_parser* p, const int n) {
    p->i = 0;
    p->n = n;
}

static int
remaining_is_done(struct response_parser* p) {
    return p->i >= p->n;
}

//////////////////////////////////////////////////////////////////////////////

static enum response_state
version(const uint8_t c, struct response_parser* p) {
    enum response_state next;
    switch (c) {
        case 0x05:
            next = response_field;
            break;
        default:
            next = response_error_unsupported_version;
            break;
    }

    return next;
}

static enum response_state
field(const uint8_t c, struct response_parser* p) {
    p->response->field = c;

    return response_rsv;
}

static enum response_state
rsv(const uint8_t c, struct response_parser* p) {
    return response_atyp;
}

static enum response_state
atyp(const uint8_t c, struct response_parser* p) {
    enum response_state next;

    p->response->dest_addr_type = c;
    switch (p->response->dest_addr_type) {
        case socks_res_addrtype_ipv4:
            remaining_set(p, 4);
            memset(&(p->response->dest_addr.ipv4), 0,
                   sizeof(p->response->dest_addr.ipv4));
            p->response->dest_addr.ipv4.sin_family = AF_INET;
            next = response_dstaddr;
            break;
        case socks_res_addrtype_ipv6:
            remaining_set(p, 16);
            memset(&(p->response->dest_addr.ipv6), 0,
                               sizeof(p->response->dest_addr.ipv6));
            p->response->dest_addr.ipv6.sin6_family = AF_INET6;
            next = response_dstaddr;
            break;
        case socks_res_addrtype_domain:
            next = response_dstaddr_fqdn;
            break;
        default:
            next = response_error_unsupported_atyp;
            break;
    }

    return next;
}

static enum response_state
dstaddr_fqdn(const uint8_t c, struct response_parser* p) {
    remaining_set(p, c);
    p->response->dest_addr.fqdn[p->n - 1] = 0;

    return response_dstaddr;
}

static enum response_state
dstaddr(const uint8_t c, struct response_parser* p) {
    enum response_state next;

    switch (p->response->dest_addr_type) {
        case socks_res_addrtype_ipv4:
            ((uint8_t *)&(p->response->dest_addr.ipv4.sin_addr))[p->i++] = c;
            break;
        case socks_res_addrtype_ipv6:
            ((uint8_t *)&(p->response->dest_addr.ipv6.sin6_addr))[p->i++] = c;
            break;
        case socks_res_addrtype_domain:
            p->response->dest_addr.fqdn[p->i++] = c;
            break;
        }
    if (remaining_is_done(p)) {
        remaining_set(p, 2);
        p->response->dest_port = 0;
        next = response_dstport;
    } else {
        next = response_dstaddr;
    }

    return next;
}

static enum response_state
dstport(const uint8_t c, struct response_parser* p) {
    enum response_state next;
    *(((uint8_t *) &(p->response->dest_port)) + p->i) = c;
    p->i++;
    next = response_dstport;
    if (p->i >= p->n) {
        next = response_done;
    }
    return next;
}

extern void
response_parser_init (struct response_parser* p) {
    p->state = response_version;
    memset(p->response, 0, sizeof(*(p->response)));
}


extern enum response_state 
response_parser_feed (struct response_parser* p, const uint8_t c) {
    enum response_state next;

    switch(p->state) {
        case response_version:
            next = version(c, p);
            break;
        case response_field:
            next = field(c, p);
            break;
        case response_rsv:
            next = rsv(c, p);
            break;
        case response_atyp:
            next = atyp(c, p);
            break;
        case response_dstaddr_fqdn:
            next = dstaddr_fqdn(c, p);
            break;
        case  response_dstaddr:
            next = dstaddr(c, p);
            break;
        case response_dstport:
            next = dstport(c, p);
            break;
        case response_done:
        case response_error:
        case response_error_unsupported_version:
        case response_error_unsupported_atyp:
            next = p->state;
            break;
        default:
            next = response_error;
            break;
    }

    return p->state = next;
}

extern bool 
response_is_done(const enum response_state st, bool *errored) {
    if(st >= response_error && errored != 0) {
        *errored = true;
    }
    return st >= response_done;
}

extern enum response_state
response_consume(buffer *b, struct response_parser *p, bool *errored) {
    enum response_state st = p->state;

    while(buffer_can_read(b)) {
       const uint8_t c = buffer_read(b);
       st = response_parser_feed(p, c);
       if(response_is_done(st, errored)) {
          break;
       }
    }
    return st;
}

extern void
response_close(struct response_parser *p) {
    // nada que hacer
}

extern int
response_marshall(buffer *b,
                 const enum socks_res_field status) {
    size_t  n;
    uint8_t *buff = buffer_write_ptr(b, &n);
    if(n < 10) {
        return -1;
    }
    buff[0] = 0x05;
    buff[1] = status;
    buff[2] = 0x00;
    buff[3] = socks_res_addrtype_ipv4;
    buff[4] = 0x00;
    buff[5] = 0x00;
    buff[6] = 0x00;
    buff[7] = 0x00;
    buff[8] = 0x00;
    buff[9] = 0x00;

    buffer_write_adv(b, 10);
    return 10;
}

enum socks_res_field
cmd_resolve(struct response* response,  struct sockaddr **originaddr,
            socklen_t *originlen, int *domain) {
    enum socks_res_field ret = socks_res_general_failure;

    *domain                  = AF_INET;
    struct sockaddr *addr    = 0x00;
    socklen_t        addrlen = 0;

    switch (response->dest_addr_type) {
        case socks_res_addrtype_domain: {
            struct hostent *hp = gethostbyname(response->dest_addr.fqdn);
            if (hp == 0) {
                memset(&response->dest_addr, 0x00,
                                       sizeof(response->dest_addr));
                break;
            } 
            response->dest_addr.ipv4.sin_family = hp->h_addrtype;
            memcpy((char *)&response->dest_addr.ipv4.sin_addr,
                   *hp->h_addr_list, hp->h_length);
            
        }
        /* no break */
        case socks_res_addrtype_ipv4:
            *domain  = AF_INET;
            addr    = (struct sockaddr *)&(response->dest_addr.ipv4);
            addrlen = sizeof(response->dest_addr.ipv4);
            response->dest_addr.ipv4.sin_port = response->dest_port;
            break;
        case socks_res_addrtype_ipv6:
            *domain  = AF_INET6;
            addr    = (struct sockaddr *)&(response->dest_addr.ipv6);
            addrlen = sizeof(response->dest_addr.ipv6);
            response->dest_addr.ipv6.sin6_port = response->dest_port;
            break;
        default:
            return socks_res_atype_not_supported;
    }

    *originaddr = addr;
    *originlen  = addrlen;

    return ret;
}

#include <errno.h>

enum socks_res_field
errno_to_socks(const int e) {
    enum socks_res_field ret = socks_res_general_failure;
    switch (e) {
        case 0:
            ret = socks_res_succeeded;
            break;
        case ECONNREFUSED:
            ret = socks_res_connection_refused;
            break;
        case EHOSTUNREACH:
            ret = socks_res_host_unreachable;
            break;
        case ENETUNREACH:
            ret = socks_res_network_unreachable;
            break;
        case ETIMEDOUT:
            ret = socks_res_ttl_expired;
            break;
    }
    return ret;
}

/* TESTS */
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

#define FIXBUF(b, data) buffer_init(&(b), N(data), (data)); \
                        buffer_write_adv(&(b), N(data))

#define N(x) (sizeof(x)/sizeof(x[0]))


int
test_unsupported_ver() {

	int ans = 0; // OK
    struct response response;
    struct response_parser parser = {
        .response = &response,
    };
    response_parser_init(&parser);
    uint8_t data[] = {
        0x04,
    };
    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum response_state st = response_consume(&b, &parser, &errored);
    
    if (true != errored){
    	ans++;
    	printf( "error in version unsupported\n");
    }
    if (response_error_unsupported_version != st){
    	ans++;
    	printf( "error in version unsupported: state trigger\n");
    }

    return ans;

}


int
test_response_connect_domain() {
	int ans = 0;
    struct response response;
    struct response_parser parser = {
        .response = &response,
    };
    response_parser_init(&parser);
    uint8_t data[] = {
        0x05, 0x00, 0x00, 0x03, 0x0f, 0x77, 0x77, 0x77, 
        0x2e, 0x69, 0x74, 0x62, 0x61, 0x2e, 0x65, 0x64, 
        0x75, 0x2e, 0x61, 0x72, 0x00, 0x50, 
    };
    buffer b; FIXBUF(b, data);
    bool errored = false;
    response_consume(&b, &parser, &errored);
    
    if ( errored != false ){
    	ans ++;
    	printf( "error in connect domain: errored\n");
    }
    if( socks_res_succeeded != response.field){
    	ans ++;
    	printf( "error in connect domain: field\n");
    }
    if ( socks_res_addrtype_domain != response.dest_addr_type){
    	ans ++;
    	printf( "error in connect domain: addrtype\n");
    }
    /* NOT RESOLVING FQDN PROPERLY */
    if ( "www.itba.edu.ar" != response.dest_addr.fqdn){
    	ans ++;
    	printf( "error in connect domain: fqdn\n");
    }
    // chequear port

    return ans;

}


int
test_response_connect_ipv4 () {
	int ans = 0;
    struct response response;
    struct response_parser parser = {
        .response = &response,
    };
    response_parser_init(&parser);

    uint8_t data[] = {
        0x05, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01,
        0x23, 0x82
    };
    buffer b; FIXBUF(b, data);
    bool errored = false;
    enum response_state st = response_consume(&b, &parser, &errored);
    
    if ( errored != false ){
    	ans ++;
    	printf( "error in connect ipv4: errored\n");
    }

    if ( response_done != st ){
    	ans ++;
    	printf( "error in connect ipv4: state\n");
    }

    if ( socks_res_succeeded != response.field ){
    	ans ++;
    	printf( "error in connect ipv4: field\n");
    }

    if ( socks_res_addrtype_ipv4 != response.dest_addr_type ){
    	ans ++;
    	printf( "error in connect ipv4: addr type\n");
    }
    //test port
    /*
    if ( htons(9090) != response.dest_port ){
    	ans ++;
    	printf( "error in connect ipv4: port\n");
    }
    */
    return ans;

}

int
test_response_connect_ipv6 () {
	int ans = 0 ;
    struct response response;
    struct response_parser parser = {
        .response = &response,
    };
    response_parser_init(&parser);

    uint8_t data[] = {
        0x05, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x23, 0x82 
    };
    buffer b; FIXBUF(b, data);
    bool errored = false;
    enum response_state st = response_consume(&b, &parser, &errored);

    if ( errored != false ){
    	ans ++;
    	printf( "error in connect ipv6: errored\n");
    }

    if ( response_done != st ){
    	ans ++;
    	printf( "error in connect ipv6: state\n");
    }

    if ( socks_res_succeeded != response.field ){
    	ans ++;
    	printf( "error in connect ipv6: field\n");
    }

    if ( socks_res_addrtype_ipv6 != response.dest_addr_type ){
    	ans ++;
    	printf( "error in connect ipv6: addr type\n");
    }

    return ans;

}


int
test_response_connect_multiple_messages() {
	int ans = 0;
    struct response response;
    struct response_parser parser = {
        .response = &response,
    };
    response_parser_init(&parser);
    uint8_t data[] = {
        // 00
        0x05, 0x00, 0x00, 0x03, 0x0f, 0x77, 0x77, 0x77,
        0x2e, 0x69, 0x74, 0x62, 0x61, 0x2e, 0x65, 0x64,
        0x75, 0x2e, 0x61, 0x72, 0x00, 0x50,
        // 01
        0x05, 0x00, 0x00, 0x03, 0x0f, 0x77, 0x77, 0x77,
        0x2e, 0x69, 0x74, 0x62, 0x61, 0x2e, 0x65, 0x64,
        0x75, 0x2e, 0x61, 0x72, 0x00, 0x50,
    };
    buffer b; FIXBUF(b, data);
    bool errored = false;
    response_consume(&b, &parser, &errored);

    if ( errored != false ){
    	ans ++;
    	printf( "error in connect domain msg 1: errored\n");
    }
    if( socks_res_succeeded != response.field){
    	ans ++;
    	printf( "error in connect domain msg 1: field\n");
    }
    if ( socks_res_addrtype_domain != response.dest_addr_type){
    	ans ++;
    	printf( "error in connect domain msg 1 : addrtype\n");
    }
    /* NOT RESOLVING FQDN PROPERLY */
    if ( "www.itba.edu.ar" != response.dest_addr.fqdn){
    	ans ++;
    	printf( "error in connect domain  msg 1: fqdn\n");
    }

    errored = false;
    memset(&response, 0, sizeof(response));
    response_parser_init(&parser);

    response_consume(&b, &parser, &errored);

    if ( errored != false ){
    	ans ++;
    	printf( "error in connect domain msg 2: errored\n");
    }
    if( socks_res_succeeded != response.field){
    	ans ++;
    	printf( "error in connect domain msg 2: field\n");
    }
    if ( socks_res_addrtype_domain != response.dest_addr_type){
    	ans ++;
    	printf( "error in connect domain msg 2: addrtype\n");
    }
    /* NOT RESOLVING FQDN PROPERLY */
    if ( "www.itba.edu.ar" != response.dest_addr.fqdn){
    	ans ++;
    	printf( "error in connect domain msg 2: fqdn\n");
    }

    return ans;
}
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/* TESTS */

int main () {
	int n, aux;

	n = test_unsupported_ver();
	aux = test_response_connect_domain();
	n = n + aux;
	aux = test_response_connect_ipv4();
	n += aux;
	aux = test_response_connect_ipv6();
	n += aux;
	aux = test_response_connect_multiple_messages();
	n += aux;

	printf( "%d\n", n );
}