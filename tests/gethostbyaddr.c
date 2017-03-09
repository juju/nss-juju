/* Copyright 2017 Canonical Ltd.
 *
 * Licensed under the AGPLv3, see LICENSE file for details.
 *
 * Name Service Switch module for resolving Juju host names.
 */

#include <check.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <arpa/inet.h>
#include "nss-juju.h"

#define NELEMENTS(A) ((sizeof((A)) / sizeof((A))[0]))

#define GETHOSTBYADDR_VARIABLES			\
	struct hostent	 hostent;		\
	char		 buffer[1024];		\
	int		 err;			\
	int		 h_err			\

#define GETHOSTBYADDR2_VARIABLES		\
	struct hostent	 hostent;		\
	char		 buffer[1024];		\
	int		 err;			\
	int		 h_err;			\
	int32_t		 ttl

extern char* _nssjuju_configfilename;

struct test_case {
	const char *name;
	const char *ip_str;
	int af;
};

static struct test_case local_testcases[] = {
	{ "juju-ip-10-11-12-13",
	  "10.11.12.13",
	  AF_INET },
	{ "juju-ip-172-17-3-4",
	  "172.17.3.4",
	  AF_INET },
	{ "juju-ip-192-168-199-101",
	  "192.168.199.101",
	  AF_INET },
	{ "juju-ip-fc80-0000-0000-0000-fc8d-e9ff-fe36-5312",
	  "fc80::fc8d:e9ff:fe36:5312",
	  AF_INET6 },
	{ "juju-ip-fd99-1234-5678-910a-bcde-f012-3456-7899",
	  "fd99:1234:5678:910a:bcde:f012:3456:7899",
	  AF_INET6 }
};

static struct test_case file_testcases[] = {
	{ "juju-ip-1-2-3-4",
	  "1.2.3.4",
	  AF_INET },
	{ "juju-ip-8-8-8-8",
	  "8.8.8.8",
	  AF_INET },
	{ "juju-ip-192-167-11-11",
	  "192.167.11.11",
	  AF_INET },
	{ "juju-ip-2001-0470-1f1d-08d8-c0db-9559-9417-2416",
	  "2001:470:1f1d:8d8:c0db:9559:9417:2416",
	  AF_INET6 },
	{ "juju-ip-4001-1470-1f1d-f8d8-c0db-9559-9417-2416",
	  "4001:1470:1f1d:f8d8:c0db:9559:9417:2416",
	  AF_INET6 }
};

static char file_testcases_str[] = "1.2.3.4\n8.8.0.0/16\n192.166.0.0/15\n2001::/16\n4001:1470:1f1d:f8d8:c0db:9559:9417:2416\n";

static size_t nhosts(struct hostent *h)
{
	size_t nhosts = 0;
	char **pptr;
	for (pptr = h->h_addr_list; *pptr != NULL; pptr++, nhosts++) {}
	return nhosts;
}

static const char *hostent_str(struct hostent *h, size_t n, char *buf)
{
	return inet_ntop(h->h_addrtype, h->h_addr_list[n], buf, INET6_ADDRSTRLEN);
}

static enum nss_status _nss_juju_gethostbyaddr_wrapper(
	int		  version,
	const void *addr,
	socklen_t len,
	int af,
	struct hostent *result,
	char *buffer,
	size_t buflen,
	int *errnop,
	int *herrnop,
	int32_t *ttlp)
{
	*ttlp = -1;

	if (version == 2) {
		return _nss_juju_gethostbyaddr2_r(
			addr,
			len,
			af,
			result,
			buffer,
			buflen,
			errnop,
			herrnop,
			ttlp);
	} else {
		return _nss_juju_gethostbyaddr_r(
			addr,
			len,
			af,
			result,
			buffer,
			buflen,
			errnop,
			herrnop);
	}
}

START_TEST(test_null_addr)
{
	const void 	*addr = NULL;
	int 		err;
	int 		h_err;
	struct hostent	result;
	char		*buffer = NULL;
	int32_t		ttl;
	enum nss_status	res;

	res = _nss_juju_gethostbyaddr_wrapper(
		_i,
		addr,
		0,
		AF_UNSPEC,
		&result,
		buffer,
		0,
		&err,
		&h_err,
		&ttl);

	fail_unless(res == NSS_STATUS_UNAVAIL);
	fail_unless(err == EINVAL);
}
END_TEST

START_TEST(test_short_buf)
{
	struct in_addr	ia;
	const void 	*addr = &ia;
	int 		err;
	int 		h_err;
	struct hostent	result;
	char		buffer[16];
	int32_t		ttl;
	enum nss_status	res;

	res = _nss_juju_gethostbyaddr_wrapper(
		_i,
		addr,
		sizeof(ia),
		AF_UNSPEC,
		&result,
		buffer,
		sizeof(buffer),
		&err,
		&h_err,
		&ttl);

	fail_unless(res == NSS_STATUS_UNAVAIL);
	fail_unless(err == EINVAL);
}
END_TEST

START_TEST(test_invalid_addrlen)
{
	struct in_addr	ia;
	const void 	*addr = &ia;
	int 		err;
	int 		h_err;
	struct hostent	result;
	char		buffer[4096];
	int32_t		ttl;
	enum nss_status	res;

	res = _nss_juju_gethostbyaddr_wrapper(
		_i,
		addr,
		10*sizeof(ia),
		AF_UNSPEC,
		&result,
		buffer,
		sizeof(buffer),
		&err,
		&h_err,
		&ttl);

	fail_unless(res == NSS_STATUS_UNAVAIL);
	fail_unless(err == EINVAL);
}
END_TEST

START_TEST(test_invalid_af)
{
	struct in_addr	ia;
	const void 	*addr = &ia;
	int 		err;
	int 		h_err;
	struct hostent	result;
	char		buffer[4096];
	int32_t		ttl;
	enum nss_status	res;

	res = _nss_juju_gethostbyaddr_wrapper(
		_i,
		addr,
		sizeof(ia),
		AF_UNSPEC,
		&result,
		buffer,
		sizeof(buffer),
		&err,
		&h_err,
		&ttl);

	fail_unless(res == NSS_STATUS_UNAVAIL);
	fail_unless(err == EINVAL);
}
END_TEST

START_TEST(test_valid_builtin)
{
	struct in6_addr	ia;
	void 		*addr = &ia;
	int 		err;
	int 		h_err;
	struct hostent	result;
	char		buffer[4096];
	enum nss_status	res;
	char ipbuf[INET6_ADDRSTRLEN];

	_nssjuju_configfilename = "";
	inet_pton(local_testcases[_i].af, local_testcases[_i].ip_str, addr);

	res = _nss_juju_gethostbyaddr_r(
		addr,
		sizeof(ia),
		local_testcases[_i].af,
		&result,
		buffer,
		sizeof(buffer),
		&err,
		&h_err);

	fail_unless(res == NSS_STATUS_SUCCESS);
	fail_unless(err == 0);
	fail_unless(h_err == 0);
	fail_unless(result.h_aliases != NULL);
	fail_unless(result.h_aliases[0] == NULL);
	fail_unless(result.h_addrtype == local_testcases[_i].af);
	fail_unless(result.h_length == (int) (local_testcases[_i].af == AF_INET6 ? sizeof(struct in6_addr) : sizeof(struct in_addr)));
	fail_unless(result.h_addr_list != NULL);
	fail_unless(result.h_addr_list[0] != NULL);
	fail_unless(result.h_addr_list[1] == NULL);
	fail_unless(nhosts(&result) == 1);
	ck_assert_str_eq(result.h_name, local_testcases[_i].name);
	ck_assert_str_eq(hostent_str(&result, 0, ipbuf), local_testcases[_i].ip_str);
}
END_TEST

START_TEST(test_valid_builtin2)
{
	struct in6_addr	ia;
	void 		*addr = &ia;
	int 		err;
	int 		h_err;
	struct hostent	result;
	char		buffer[4096];
	int32_t		ttl;
	enum nss_status	res;
	char ipbuf[INET6_ADDRSTRLEN];

	_nssjuju_configfilename = "";
	inet_pton(local_testcases[_i].af, local_testcases[_i].ip_str, addr);

	res = _nss_juju_gethostbyaddr2_r(
		addr,
		sizeof(ia),
		local_testcases[_i].af,
		&result,
		buffer,
		sizeof(buffer),
		&err,
		&h_err,
		&ttl);

	fail_unless(res == NSS_STATUS_SUCCESS);
	fail_unless(err == 0);
	fail_unless(h_err == 0);
	fail_unless(result.h_aliases != NULL);
	fail_unless(result.h_aliases[0] == NULL);
	fail_unless(result.h_addrtype == local_testcases[_i].af);
	fail_unless(result.h_length == (int) (local_testcases[_i].af == AF_INET6 ? sizeof(struct in6_addr) : sizeof(struct in_addr)));
	fail_unless(result.h_addr_list != NULL);
	fail_unless(result.h_addr_list[0] != NULL);
	fail_unless(result.h_addr_list[1] == NULL);
	fail_unless(nhosts(&result) == 1);
	ck_assert_str_eq(result.h_name, local_testcases[_i].name);
	ck_assert_str_eq(hostent_str(&result, 0, ipbuf), local_testcases[_i].ip_str);
	fail_unless(ttl == 0);
}
END_TEST

START_TEST(test_valid_file)
{
	struct in6_addr	ia;
	void 		*addr = &ia;
	int 		err;
	int 		h_err;
	struct hostent	result;
	char		buffer[4096];
	enum nss_status	res;
	char 		ipbuf[INET6_ADDRSTRLEN];
	int 		fd;
	char 		templ[] = "/tmp/tempXXXXXX";

	fd = mkstemp(templ);
	fail_unless(fd > 0);
	_nssjuju_configfilename = templ;
	write(fd, file_testcases_str, sizeof(file_testcases_str));
	close(fd);

	inet_pton(file_testcases[_i].af, file_testcases[_i].ip_str, addr);

	res = _nss_juju_gethostbyaddr_r(
		addr,
		sizeof(ia),
		file_testcases[_i].af,
		&result,
		buffer,
		sizeof(buffer),
		&err,
		&h_err);

	fail_unless(res == NSS_STATUS_SUCCESS);
	fail_unless(err == 0);
	fail_unless(h_err == 0);
	fail_unless(result.h_aliases != NULL);
	fail_unless(result.h_aliases[0] == NULL);
	fail_unless(result.h_addrtype == file_testcases[_i].af);
	fail_unless(result.h_length == (int) (file_testcases[_i].af == AF_INET6 ? sizeof(struct in6_addr) : sizeof(struct in_addr)));
	fail_unless(result.h_addr_list != NULL);
	fail_unless(result.h_addr_list[0] != NULL);
	fail_unless(result.h_addr_list[1] == NULL);
	fail_unless(nhosts(&result) == 1);
	ck_assert_str_eq(result.h_name, file_testcases[_i].name);
	ck_assert_str_eq(hostent_str(&result, 0, ipbuf), file_testcases[_i].ip_str);
}
END_TEST

START_TEST(test_valid_file2)
{
	struct in6_addr	ia;
	void 		*addr = &ia;
	int 		err;
	int 		h_err;
	struct hostent	result;
	char		buffer[4096];
	int32_t		ttl;
	enum nss_status	res;
	char ipbuf[INET6_ADDRSTRLEN];
	int 		fd;
	char 		templ[] = "/tmp/tempXXXXXX";

	fd = mkstemp(templ);
	fail_unless(fd > 0);
	_nssjuju_configfilename = templ;
	write(fd, file_testcases_str, sizeof(file_testcases_str));
	close(fd);

	inet_pton(file_testcases[_i].af, file_testcases[_i].ip_str, addr);

	res = _nss_juju_gethostbyaddr2_r(
		addr,
		sizeof(ia),
		file_testcases[_i].af,
		&result,
		buffer,
		sizeof(buffer),
		&err,
		&h_err,
		&ttl);

	fail_unless(res == NSS_STATUS_SUCCESS);
	fail_unless(err == 0);
	fail_unless(h_err == 0);
	fail_unless(result.h_aliases != NULL);
	fail_unless(result.h_aliases[0] == NULL);
	fail_unless(result.h_addrtype == file_testcases[_i].af);
	fail_unless(result.h_length == (int) (file_testcases[_i].af == AF_INET6 ? sizeof(struct in6_addr) : sizeof(struct in_addr)));
	fail_unless(result.h_addr_list != NULL);
	fail_unless(result.h_addr_list[0] != NULL);
	fail_unless(result.h_addr_list[1] == NULL);
	fail_unless(nhosts(&result) == 1);
	ck_assert_str_eq(result.h_name, file_testcases[_i].name);
	ck_assert_str_eq(hostent_str(&result, 0, ipbuf), file_testcases[_i].ip_str);
	fail_unless(ttl == 0);
}
END_TEST

START_TEST(test_nonexistent_builtin)
{
	struct in6_addr	ia;
	void 		*addr = &ia;
	int 		err;
	int 		h_err;
	struct hostent	result;
	char		buffer[4096];
	enum nss_status	res;

	_nssjuju_configfilename = "";
	inet_pton(file_testcases[_i].af, file_testcases[_i].ip_str, addr);

	res = _nss_juju_gethostbyaddr_r(
		addr,
		sizeof(ia),
		file_testcases[_i].af,
		&result,
		buffer,
		sizeof(buffer),
		&err,
		&h_err);

	fail_unless(err == ENOENT);
	fail_unless(h_err == HOST_NOT_FOUND);
	fail_unless(res == NSS_STATUS_NOTFOUND);
}
END_TEST

START_TEST(test_nonexistent_builtin2)
{
	struct in6_addr	ia;
	void 		*addr = &ia;
	int 		err;
	int 		h_err;
	struct hostent	result;
	char		buffer[4096];
	int32_t		ttl;
	enum nss_status	res;

	_nssjuju_configfilename = "";
	inet_pton(file_testcases[_i].af, file_testcases[_i].ip_str, addr);

	res = _nss_juju_gethostbyaddr2_r(
		addr,
		sizeof(ia),
		file_testcases[_i].af,
		&result,
		buffer,
		sizeof(buffer),
		&err,
		&h_err,
		&ttl);

	fail_unless(err == ENOENT);
	fail_unless(h_err == HOST_NOT_FOUND);
	fail_unless(res == NSS_STATUS_NOTFOUND);
}
END_TEST

START_TEST(test_nonexistent_file)
{
	struct in6_addr	ia;
	void 		*addr = &ia;
	int 		err;
	int 		h_err;
	struct hostent	result;
	char		buffer[4096];
	enum nss_status	res;
	int 		fd;
	char 		templ[] = "/tmp/tempXXXXXX";

	fd = mkstemp(templ);
	fail_unless(fd > 0);
	_nssjuju_configfilename = templ;
	write(fd, file_testcases_str, sizeof(file_testcases_str));
	close(fd);

	inet_pton(local_testcases[_i].af, local_testcases[_i].ip_str, addr);

	res = _nss_juju_gethostbyaddr_r(
		addr,
		sizeof(ia),
		local_testcases[_i].af,
		&result,
		buffer,
		sizeof(buffer),
		&err,
		&h_err);

	fail_unless(err == ENOENT);
	fail_unless(h_err == HOST_NOT_FOUND);
	fail_unless(res == NSS_STATUS_NOTFOUND);
}
END_TEST

START_TEST(test_nonexistent_file2)
{
	struct in6_addr	ia;
	void 		*addr = &ia;
	int 		err;
	int 		h_err;
	struct hostent	result;
	char		buffer[4096];
	int32_t		ttl;
	enum nss_status	res;
	int 		fd;
	char 		templ[] = "/tmp/tempXXXXXX";

	fd = mkstemp(templ);
	fail_unless(fd > 0);
	_nssjuju_configfilename = templ;
	write(fd, file_testcases_str, sizeof(file_testcases_str));
	close(fd);

	inet_pton(local_testcases[_i].af, local_testcases[_i].ip_str, addr);

	res = _nss_juju_gethostbyaddr2_r(
		addr,
		sizeof(ia),
		local_testcases[_i].af,
		&result,
		buffer,
		sizeof(buffer),
		&err,
		&h_err,
		&ttl);

	fail_unless(err == ENOENT);
	fail_unless(h_err == HOST_NOT_FOUND);
	fail_unless(res == NSS_STATUS_NOTFOUND);
}
END_TEST



static Suite *libnss_juju_suite(void)
{
	Suite *s = suite_create("nss-juju");
	TCase *tc = tcase_create("gethostbyaddr");
	tcase_add_loop_test(tc, test_null_addr, 1, 3);
	tcase_add_loop_test(tc, test_short_buf, 1, 3);
	tcase_add_loop_test(tc, test_invalid_addrlen, 1, 3);
	tcase_add_loop_test(tc, test_invalid_af, 1, 3);
	tcase_add_loop_test(tc, test_valid_builtin, 0, NELEMENTS(local_testcases));
	tcase_add_loop_test(tc, test_valid_builtin2, 0, NELEMENTS(local_testcases));
	tcase_add_loop_test(tc, test_valid_file, 0, NELEMENTS(file_testcases));
	tcase_add_loop_test(tc, test_valid_file2, 0, NELEMENTS(file_testcases));
	tcase_add_loop_test(tc, test_nonexistent_builtin, 0, NELEMENTS(file_testcases));
	tcase_add_loop_test(tc, test_nonexistent_builtin2, 0, NELEMENTS(file_testcases));
	tcase_add_loop_test(tc, test_nonexistent_file, 0, NELEMENTS(local_testcases));
	tcase_add_loop_test(tc, test_nonexistent_file2, 0, NELEMENTS(local_testcases));
	suite_add_tcase(s, tc);
	return s;
}

int main(void)
{
	int number_failed;
	Suite *s = libnss_juju_suite();
	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
