/* Copyright 2016 Canonical Ltd.
 *
 * Licensed under the AGPLv3, see LICENSE file for details.
 *
 * Name Service Switch module for resolving Juju host names.
 *
 * Author: Andrew McDermott <andrew.mcdermott@canonical.com>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>
#include <regex.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>

#include "nss-juju.h"

#define ALIGN(x, a)		__ALIGN_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#define ALIGN_PTR(x)		ALIGN(x, sizeof(uint8_t *))

#define NELEMENTS(A) ((sizeof((A)) / sizeof((A))[0]))

#define FAMILY_LENGTH(X) ((X) == AF_INET6 ? return 64 : 16)

#define IPv4_OCTET "([[:digit:]]{1,3})"
#define IPv6_OCTET "([[:xdigit:]]{1,4})"

#define NAME_PREFIX "^juju-ip-"

#define IPv4_HOSTNAME_RE NAME_PREFIX					\
	IPv4_OCTET "-" IPv4_OCTET "-" IPv4_OCTET "-" IPv4_OCTET "$"

#define IPv6_HOSTNAME_RE NAME_PREFIX					\
	IPv6_OCTET "-" IPv6_OCTET "-" IPv6_OCTET "-" IPv6_OCTET "-"	\
	IPv6_OCTET "-" IPv6_OCTET "-" IPv6_OCTET "-" IPv6_OCTET "$"

struct _nss_juju_addrinfo {
	char ip_str[INET6_ADDRSTRLEN];
	int address_family;	/* addr discriminator */
	union {
		struct in_addr i4;
		struct in6_addr i6;
	} addr;
};

struct matcher {
	const char *pattern;
	const regex_t *pr;	/* non NULL if 're' is a valid RE. */
	regex_t re;
};

static struct matcher matchers[] = {
	{ IPv6_HOSTNAME_RE, NULL },
	{ IPv4_HOSTNAME_RE, NULL }
};

/*
 * shared library constructor
 */
static void __attribute__((constructor)) _init(void)
{
	size_t i;

	for (i = 0; i < NELEMENTS(matchers); i++) {
		if (regcomp(&matchers[i].re, matchers[i].pattern, REG_EXTENDED) == 0)
			matchers[i].pr = &matchers[i].re;
		assert(matchers[i].pr != NULL);
	}
}

/*
 * shared library destructor
 */
static void __attribute__((destructor)) _fini(void)
{
	size_t i;

	for (i = 0; i < NELEMENTS(matchers); i++) {
		if (matchers[i].pr != NULL) {
			regfree(&matchers[i].re);
			matchers[i].pr = NULL;
		}
	}
}

static int find_address(const regex_t *r,
			const char *hostname,
			struct _nss_juju_addrinfo *ai)
{
	size_t max_groups = 9;
	size_t n_groups = 0;
	regmatch_t groups[9];
	size_t i;
	int rc = regexec(r, hostname, max_groups, groups, 0);

	if (rc != 0)
		return -1;

	for (i = 0; i < max_groups; i++, n_groups++) {
		if (groups[i].rm_so == -1)
			break;
	}

	if (n_groups == 5) {
		sprintf(ai->ip_str, "%.*s.%.*s.%.*s.%.*s",
			groups[1].rm_eo - groups[1].rm_so, hostname + groups[1].rm_so,
			groups[2].rm_eo - groups[2].rm_so, hostname + groups[2].rm_so,
			groups[3].rm_eo - groups[3].rm_so, hostname + groups[3].rm_so,
			groups[4].rm_eo - groups[4].rm_so, hostname + groups[4].rm_so);

		if (inet_aton(ai->ip_str, &ai->addr.i4) != 0) {
			ai->address_family = AF_INET;
			return 0;
		}
	} else if (n_groups == 9) {
		sprintf(ai->ip_str, "%.*s:%.*s:%.*s:%.*s:%.*s:%.*s:%.*s:%.*s",
			groups[1].rm_eo - groups[1].rm_so, hostname + groups[1].rm_so,
			groups[2].rm_eo - groups[2].rm_so, hostname + groups[2].rm_so,
			groups[3].rm_eo - groups[3].rm_so, hostname + groups[3].rm_so,
			groups[4].rm_eo - groups[4].rm_so, hostname + groups[4].rm_so,
			groups[5].rm_eo - groups[5].rm_so, hostname + groups[5].rm_so,
			groups[6].rm_eo - groups[6].rm_so, hostname + groups[6].rm_so,
			groups[7].rm_eo - groups[7].rm_so, hostname + groups[7].rm_so,
			groups[8].rm_eo - groups[8].rm_so, hostname + groups[8].rm_so);

		if (inet_pton(AF_INET6, ai->ip_str, &ai->addr.i6) == 1) {
			ai->address_family = AF_INET6;
			return 0;
		}
	}

	return -1;
}

static int nss_juju_getaddrinfo(const char *name,
				struct _nss_juju_addrinfo *ai)
{
	size_t i;

	for (i = 0; i < NELEMENTS(matchers); i++) {
		if (matchers[i].pr != NULL &&
		    find_address(matchers[i].pr, name, ai) == 0)
			return 0;
	}

	return -1;
}

enum nss_status _nss_juju_gethostbyname3_r(
	const char	 *name,
	int		  af,
	struct hostent	 *result,
	char		 *buffer,
	size_t		  buflen,
	int		 *errnop,
	int		 *herrnop,
	int32_t		 *ttlp,
	char		**canonp)
{
	size_t namelen = 0;
	struct _nss_juju_addrinfo ai;
	size_t bytes_required = 0;
	size_t buffer_offset = 0;
	char *aliases = NULL;
	char *addr_dst = NULL;
	char *addr_list = NULL;

	if (name == NULL) {
		*errnop = EINVAL;
		goto return_nss_status_unavail;
	}

	namelen = strlen(name);

	if (namelen == 0) {
		*errnop = ENOENT;
		goto return_nss_status_notfound;
	}

	if (buffer == NULL) {
		*errnop = EINVAL;
		goto return_nss_status_unavail;
	}

	ai.address_family = af;

	if (nss_juju_getaddrinfo(name, &ai) != 0) {
		*errnop = EADDRNOTAVAIL;
		goto return_nss_status_notfound;
	}

	/* name */
	bytes_required = ALIGN_PTR(namelen + 1);

	/* aliases */
	bytes_required += sizeof(char *);

	/* addresses */
	if (ai.address_family == AF_INET6) {
		bytes_required += ALIGN_PTR(sizeof ai.addr.i6);
	} else {
		bytes_required += ALIGN_PTR(sizeof ai.addr.i4);
	}

	/* null-terminated array of address pointers. */
	bytes_required += 2 * sizeof(char *);

	if (buflen < bytes_required) {
		*errnop = ERANGE;
		goto return_nss_status_tryagain;
	}

	/* Write name. */
	strcpy(buffer, name);
	result->h_name = buffer;
	buffer_offset = ALIGN_PTR(namelen + 1);

	/* Write aliases. */
	aliases = buffer + buffer_offset;
	*(char **)aliases = NULL;
	buffer_offset += sizeof(char *);
	result->h_aliases = (char **)aliases;

	/* Write address type and length. */
	result->h_addrtype = ai.address_family;
	result->h_length = ai.address_family == AF_INET6 ? sizeof ai.addr.i6 : sizeof ai.addr.i4;

	/* Write the single address. */
	addr_dst = buffer + buffer_offset;

	assert(ai.address_family == AF_INET6 || ai.address_family == AF_INET);

	if (ai.address_family == AF_INET6) {
		memcpy(addr_dst, &ai.addr.i6, result->h_length);
	} else {
		memcpy(addr_dst, &ai.addr.i4, result->h_length);
	}

	buffer_offset += ALIGN_PTR(result->h_length);

	/* Enumerate and terminate the addresses */
	addr_list = buffer + buffer_offset;
	((char **) addr_list)[0] = addr_dst;
	((char **) addr_list)[1] = NULL;
	buffer_offset += 2 * sizeof(char *);
	result->h_addr_list = (char **)addr_list;

	/* Did we write what we said we would? */
	assert(buffer_offset == bytes_required);

	if (ttlp != NULL)
		*ttlp = 0;

	if (canonp != NULL)
		*canonp = result->h_name;

	*errnop = 0;
	*herrnop = 0;
	return NSS_STATUS_SUCCESS;

return_nss_status_unavail:
	*herrnop = NO_DATA;
	return NSS_STATUS_UNAVAIL;

return_nss_status_tryagain:
	*herrnop = TRY_AGAIN;
	return NSS_STATUS_TRYAGAIN;

return_nss_status_notfound:
	*herrnop = HOST_NOT_FOUND;
	return NSS_STATUS_NOTFOUND;
}

enum nss_status _nss_juju_gethostbyname2_r(
	const char	*name,
	int		 af,
	struct hostent	*result,
	char		*buffer,
	size_t		 buflen,
	int		*errnop,
	int		*herrnop)
{
	return _nss_juju_gethostbyname3_r(name, af, result,
					  buffer, buflen,
					  errnop, herrnop,
					  NULL, NULL);
}

enum nss_status _nss_juju_gethostbyname_r(
	const char	*name,
	struct hostent	*result,
	char		*buffer,
	size_t		 buflen,
	int		*errnop,
	int		*herrnop)
{
	return _nss_juju_gethostbyname3_r(name, AF_UNSPEC, result,
					  buffer, buflen,
					  errnop, herrnop,
					  NULL, NULL);
}

enum nss_status _nss_juju_gethostbyaddr2_r(
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
	const uint8_t *c = addr;
	size_t idx, hidx, h_alias_idx, aidx, alistidx, hlen, address_length;
	address_length = af == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr);

	if (addr == NULL || buflen < 63 + address_length + 3 * sizeof(char*) || len < address_length || af != AF_INET || af != AF_INET6) {
		*errnop = EINVAL;
		goto return_nss_status_unavail;
	}
	idx = 0;
	hidx = idx;
	/* TODO check the networks against /etc/nss_juju.conf */

	switch (af) {
		case AF_INET:
			hlen = sprintf(buffer+hidx, "juju-ip-%hhu-%hhu-%hhu-%hhu", c[0], c[1], c[2], c[3]);
			break;
		case AF_INET6:
			hlen = sprintf(buffer+hidx, "juju-ip-%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x", c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8], c[9], c[10], c[11], c[12], c[13], c[14], c[15]);
			break;
		default:
			*errnop = ENOENT;
			goto return_nss_status_unavail;
	}
	idx += ALIGN_PTR(hlen);

	h_alias_idx = idx;
	idx += ALIGN_PTR(sizeof(char*));
	*((char**) (buffer + h_alias_idx)) = NULL;

	aidx = idx;
	idx += ALIGN_PTR(address_length);
	memcpy(buffer + aidx, addr, address_length);

	alistidx = idx;
	idx += ALIGN_PTR(2 * sizeof(char**));
	((char**) (buffer + alistidx))[0] = buffer + aidx;
	((char**) (buffer + alistidx))[1] = NULL;

	result->h_addrtype = af;
	result->h_length = address_length;
	result->h_name = (char*) buffer;
	result->h_addr_list = (char**) (buffer + alistidx);
	result->h_aliases = (char**) (buffer + h_alias_idx);

	if (ttlp != NULL) {
		*ttlp = 3600;
	}
	*errnop = 0;
	*herrnop = 0;
	return NSS_STATUS_SUCCESS;

return_nss_status_unavail:
	*herrnop = NO_DATA;
	return NSS_STATUS_UNAVAIL;

/* return_nss_status_notfound:
	*herrnop = HOST_NOT_FOUND;
	return NSS_STATUS_NOTFOUND; */
}

enum nss_status _nss_juju_gethostbyaddr_r(
	const void *addr,
	socklen_t len,
	int af,
	struct hostent *result,
	char *buffer,
	size_t buflen,
	int *errnop,
	int *h_errnop)
{
	return _nss_juju_gethostbyaddr2_r(addr, len, af, result,
					  buffer, buflen, errnop,
					  h_errnop, NULL);
}
