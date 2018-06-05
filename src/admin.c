/**
 * admin.c -- parser del admin de SOCKS5 que recive la llamada
 * TODO emprolijar
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "admin.h"

static enum admin_state version_check(const uint8_t b, struct admin_parser* p);
static enum admin_state password_check(const uint8_t b, struct admin_parser* p);
static enum admin_state method_recon(const uint8_t b, struct admin_parser* p);
static enum admin_state method_check(const uint8_t b, struct admin_parser* p);
static void remaining_set(struct admin_parser* p, const int n);
static int remaining_is_done(struct admin_parser* p);
/**
TODO def
*/
extern void
admin_parser_init (struct admin_parser *p) {
	p->state     = admin_version;
	remaining_set(p, ADMIN_VERSION_LEN);
	memset(p->request, 0, sizeof(*(p->request)));
}

/**
Parse the given byte on current parser state and
trigger required transitions if applies
*/
extern enum admin_state
admin_parser_feed (struct admin_parser *p, uint8_t b) {
	switch (p->state) {
	case admin_version:
				p->state = version_check(b, p);
			break;
		case admin_done_field_version:
			p->state = admin_error_bad_request;
			if (b == SP)
				p->state = admin_secret_pass;
			break;
		case admin_secret_pass:
			p->state = password_check(b, p);
			break;
		case admin_done_field_password:
			p->state = admin_error_bad_request;
			if (b == SP)
				p->state = admin_recon_method;
			break;
		case admin_recon_method:
			p->state = method_recon(b, p);
			break;
		case admin_check_method:
			p->state = method_check(b, p);
			break;
		case admin_done_field_method:
			p->state = admin_error_bad_request;
			if (b == SP)
				p->state = admin_data;
			break;
		case admin_data:
			// p->state = parse_data(b, p);
			p->state = admin_done_field_data;
			break;
		case admin_done_field_data:
			p->state = admin_error_bad_request;
			if (b == CR)
				p->state = admin_done_request;
			break;
		case admin_done_request:
			p->state = admin_error_bad_request;
			if (b == CR)
				p->state = admin_done_request;
			if (b == LF)
				p->state = admin_done;
			break;
		case admin_done:
		case admin_error_unsupported_version:
		case admin_error_bad_passcode:
		case admin_error_bad_method:
		case admin_error_bad_request:
			break;

		default:
			fprintf(stderr, "admin request unknown state %d\n", p->state);
			abort();
		}
		return p->state;
	}

	/**
	Read admin version protocol.
	Change parser state when done
	*/
	static enum admin_state
	version_check(const uint8_t b, struct admin_parser* p) {

	if (remaining_is_done(p)) {
		if (b == '1' || b == '0') { //TODO por ahora admin v1 y v2, seria mejor un array en el .h con todas las versiones compatibles
			p->request->admin_version = b;
			remaining_set(p, ADMIN_SECRET_PASS_STRING_LEN - 1);
			return admin_done_field_version;
		}
		return admin_error_unsupported_version;
	}
	if (ADMIN_VERSION_STRING[p->i] == b) {
		p->i++;

		return admin_version;
	}

	return admin_error_unsupported_version;
}

/**
Read admin passcode.
Change parser state when done.
*/
static enum admin_state
password_check(const uint8_t b, struct admin_parser* p) {

	if (remaining_is_done(p)) { //termine de leer la pass y b es lo que viene justo dsps de la pass
		if (b == SP) { //leo el espacio y me salteo el primer estado espacio
			remaining_set(p, ADMIN_METHOD_MAX_LENGTH - 1);
			return admin_recon_method;
		}
		return admin_error_bad_passcode;
	}
	if (ADMIN_SECRET_PASS_STRING[p->i] == b) {
		p->i++;
		return admin_secret_pass;
	}
	return admin_error_bad_passcode;
}

/**
* Recognize method from first char
*/
static enum admin_state
method_recon(const uint8_t b, struct admin_parser* p) {
	if ('m' == b) {
		remaining_set(p, METRICS_LEN);
		p->i = 1;
		p->request->method = metrics;
		return admin_check_method;
	} else if ('l' == b) {
		remaining_set(p, LOGS_LEN);
		p->i = 1;
		p->request->method = logs;
		return admin_check_method;
	} else if ('e' == b) {
		remaining_set(p, ENABLE_TRANSFORMER_LEN);
		p->i = 1;
		p->request->method = enable_transformer;
		return admin_check_method;
	} else if ('d' == b) {
		remaining_set(p, DISABLE_TRANSFORMER_LEN);
		p->i = 1;
		p->request->method = disable_transformer;
		return admin_check_method;
	}
	return admin_error_bad_method;
}

/**
* Check potencial method confirms
*/
static enum admin_state
method_check(const uint8_t b, struct admin_parser* p) {
	char dst[50];
	sprintf(dst, "method recon::: received >%c<", b);
	LOG_DEBUG(dst);
	
	//primero chequeo byte
	if (ADMIN_METHOD_STRING[p->request->method][p->i] == b) {
		p->i++;
		
		if (remaining_is_done(p)) {
			LOG_DEBUG("method recon ::: remaining_is_done");
			return admin_done_request;
		}

		return admin_check_method;
	}

	return admin_error_bad_method;
}

/**
If for the current state, all input
 expected has been received.
*/
static int
remaining_is_done(struct admin_parser* p) {
	return p->i >= p->n;
}

/**
Resets i and n indexes for next section parsing
*/
static void
remaining_set(struct admin_parser* p, const int n) {
	p->i = 0;
	p->n = n;
}

extern enum admin_state
admin_consume(buffer *b, struct admin_parser *p, bool *errored) {
	enum admin_state st = p->state;
	char dst[50];
	sprintf(dst, "Admin Consume::: state pre while >%d<", st); LOG_DEBUG(dst);
	while (buffer_can_read(b)) {
		const uint8_t c = buffer_read(b);
		st = admin_parser_feed(p, c);
		sprintf(dst, "Admin Consume::: state while >%d<", st); LOG_DEBUG(dst);
		if (admin_is_done(st, errored)) {
			sprintf(dst, "Admin Consume::: done!"); LOG_DEBUG(dst);
			break;
		}
	}
	return st;
}

extern bool
admin_is_done(const enum admin_state st, bool *errored) {
	if (st > admin_done) {
		LOG_DEBUG("admin.c ::: admin_is_done st>admin_done");
		*errored = true;
	}
	return st >= admin_done;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
/* TESTS */
#define FIXBUF(b, data) buffer_init(&(b), N(data), (data)); \
                        buffer_write_adv(&(b), N(data))

#define N(x) (sizeof(x)/sizeof(x[0]))
void test_unsupported_version();
void test_supported_version();
void test_bad_password();
void test_blank_password();
void test_bad_method();
void test_metrics();
void test_logs();
void test_with_transformer();
void test_without_transformer();

// int main () {

// 	LOG_PRIORITY("Starting new test suit of admin.c");

// 	test_unsupported_version();
// 	test_bad_password();
// 	test_blank_password();
// 	test_bad_method();
// 	test_metrics();
// 	test_logs();
// 	test_with_transformer();
// 	test_without_transformer();
	
// }

void test_unsupported_version() {
	LOG_DEBUG("Testing admin request with unsupported version");
	struct admin_request request;
	struct admin_parser parser = {
		.request = &request,
	};
	admin_parser_init(&parser);
	uint8_t data[] = "ADMIN_V2";
	buffer b;
	FIXBUF(b, data);
	bool errored = false;
	enum admin_state st = admin_consume(&b, &parser, &errored);

	assert(errored);
	assert(st == admin_error_unsupported_version);
}

void test_bad_password() {
	LOG_DEBUG("Testing admin request with bad password but good version");
	struct admin_request request;
	struct admin_parser parser = {
		.request = &request,
	};
	admin_parser_init(&parser);
	uint8_t data[] = "ADMIN_V1 test_bad_password";
	buffer b;
	FIXBUF(b, data);
	bool errored = false;
	enum admin_state st = admin_consume(&b, &parser, &errored);

	assert(errored);
	assert(st == admin_error_bad_passcode);
}

void test_blank_password() {
	LOG_DEBUG("Testing admin request with blank password but good version");
	struct admin_request request;
	struct admin_parser parser = {
		.request = &request,
	};
	admin_parser_init(&parser);
	uint8_t data[] = "ADMIN_V1  ";
	buffer b;
	FIXBUF(b, data);
	bool errored = false;
	enum admin_state st = admin_consume(&b, &parser, &errored);

	assert(errored);
	assert(st == admin_error_bad_passcode);
}

void test_bad_method() {
	LOG_DEBUG("Testing admin request with bad method but good version and password");
	struct admin_request request;
	struct admin_parser parser = {
		.request = &request,
	};
	admin_parser_init(&parser);
	uint8_t data[] = "ADMIN_V1 admin test_bad_method";
	buffer b;
	FIXBUF(b, data);
	bool errored = false;
	enum admin_state st = admin_consume(&b, &parser, &errored);

	assert(errored);
	assert(st == admin_error_bad_method);
}

void test_metrics() {
	LOG_DEBUG("Testing admin with valid metrics request");
	struct admin_request request;
	struct admin_parser parser = {
		.request = &request,
	};
	admin_parser_init(&parser);
	uint8_t data[] = "ADMIN_V1 admin metrics\r\n";
	buffer b;
	FIXBUF(b, data);
	bool errored = false;
	enum admin_state st = admin_consume(&b, &parser, &errored);

	assert(!errored); //TODO esto esta tirando error por algo
	assert(st == admin_done);
}

void test_logs() {
	LOG_DEBUG("Testing admin with valid logs request");
	struct admin_request request;
	struct admin_parser parser = {
		.request = &request,
	};
	admin_parser_init(&parser);
	uint8_t data[] = "ADMIN_V1 admin logs\r\n";
	buffer b;
	FIXBUF(b, data);
	bool errored = false;
	enum admin_state st = admin_consume(&b, &parser, &errored);

	assert(!errored);
	assert(st == admin_done);
}

void test_with_transformer() {
	LOG_DEBUG("Testing admin with valid enable tranform request");
	struct admin_request request;
	struct admin_parser parser = {
		.request = &request,
	};
	admin_parser_init(&parser);
	uint8_t data[] = "ADMIN_V1 admin enable_transformer\r\n";
	buffer b;
	FIXBUF(b, data);
	bool errored = false;
	enum admin_state st = admin_consume(&b, &parser, &errored);

	assert(!errored);
	assert(st == admin_done);
}

void test_without_transformer() {
	LOG_DEBUG("Testing admin with valid disable_transformer request");
	struct admin_request request;
	struct admin_parser parser = {
		.request = &request,
	};
	admin_parser_init(&parser);
	uint8_t data[] = "ADMIN_V1 admin disable_transformer\r\n";
	buffer b;
	FIXBUF(b, data);
	bool errored = false;
	enum admin_state st = admin_consume(&b, &parser, &errored);

	assert(!errored);
	assert(st == admin_done);
}









