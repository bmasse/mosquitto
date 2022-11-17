/*
Copyright (c) 2009-2020 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

Contributors:
   Roger Light - initial implementation and documentation.
*/

#define _GNU_SOURCE
#include "config.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#ifndef WIN32
#define _GNU_SOURCE
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#ifdef __ANDROID__
#include <linux/in.h>
#include <linux/in6.h>
#include <sys/endian.h>
#endif

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif

#ifdef WITH_UNIX_SOCKETS
#  include <sys/un.h>
#endif

#ifdef __QNX__
#include <net/netbyte.h>
#endif

#ifdef WITH_TLS
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/ui.h>
#include <tls_mosq.h>
#endif

#ifdef WITH_BROKER
#  include "mosquitto_broker_internal.h"
#  ifdef WITH_WEBSOCKETS
#    include <libwebsockets.h>
#  endif
#else
#  include "read_handle.h"
#endif

#include "logging_mosq.h"
#include "memory_mosq.h"
#include "mqtt_protocol.h"
#include "net_mosq.h"
#include "time_mosq.h"
#include "util_mosq.h"

#ifdef WITH_TLS
int tls_ex_index_mosq = -1;
UI_METHOD *_ui_method = NULL;

static bool is_tls_initialized = false;

/* Functions taken from OpenSSL s_server/s_client */
static int ui_open(UI *ui)
{
	return UI_method_get_opener(UI_OpenSSL())(ui);
}

static int ui_read(UI *ui, UI_STRING *uis)
{
	return UI_method_get_reader(UI_OpenSSL())(ui, uis);
}

static int ui_write(UI *ui, UI_STRING *uis)
{
	return UI_method_get_writer(UI_OpenSSL())(ui, uis);
}

static int ui_close(UI *ui)
{
	return UI_method_get_closer(UI_OpenSSL())(ui);
}

static void setup_ui_method(void)
{
	_ui_method = UI_create_method("OpenSSL application user interface");
	UI_method_set_opener(_ui_method, ui_open);
	UI_method_set_reader(_ui_method, ui_read);
	UI_method_set_writer(_ui_method, ui_write);
	UI_method_set_closer(_ui_method, ui_close);
}

static void cleanup_ui_method(void)
{
	if(_ui_method){
		UI_destroy_method(_ui_method);
		_ui_method = NULL;
	}
}

UI_METHOD *net__get_ui_method(void)
{
	return _ui_method;
}

#endif

int net__init(void)
{
	return MOSQ_ERR_SUCCESS;
}

void net__cleanup(void)
{
#  if OPENSSL_VERSION_NUMBER < 0x10100000L
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
	ERR_remove_thread_state(NULL);
	EVP_cleanup();

	is_tls_initialized = false;
#  endif

	CONF_modules_unload(1);
	cleanup_ui_method();


}

static void net__init_tls(void)
{
	BTraceIn
	if(is_tls_initialized) return;

#  if OPENSSL_VERSION_NUMBER < 0x10100000L
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();
#  else
	OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS \
			| OPENSSL_INIT_ADD_ALL_DIGESTS \
			| OPENSSL_INIT_LOAD_CONFIG, NULL);
#  endif
	//setup_ui_method();
	if(tls_ex_index_mosq == -1){
		tls_ex_index_mosq = SSL_get_ex_new_index(0, "client context", NULL, NULL, NULL);
	}

	is_tls_initialized = true;
	BTraceOut
}

/* Close a socket associated with a context and set it to -1.
 * Returns 1 on failure (context is NULL)
 * Returns 0 on success.
 */
int net__socket_close(struct mosquitto *mosq)
{
	int rc = 0;

	assert(mosq);
#ifdef WITH_TLS
	{
		if(mosq->ssl){
			if(!SSL_in_init(mosq->ssl)){
				SSL_shutdown(mosq->ssl);
			}
			SSL_free(mosq->ssl);
			mosq->ssl = NULL;
		}
	}
#endif

	{
		if(mosq->sock != INVALID_SOCKET){
			rc = COMPAT_CLOSE(mosq->sock);
			mosq->sock = INVALID_SOCKET;
		}
	}


	return rc;
}


#ifdef FINAL_WITH_TLS_PSK
static unsigned int psk_client_callback(SSL *ssl, const char *hint,
		char *identity, unsigned int max_identity_len,
		unsigned char *psk, unsigned int max_psk_len)
{
	struct mosquitto *mosq;
	int len;

	UNUSED(hint);

	mosq = SSL_get_ex_data(ssl, tls_ex_index_mosq);
	if(!mosq) return 0;

	snprintf(identity, max_identity_len, "%s", mosq->tls_psk_identity);

	len = mosquitto__hex2bin(mosq->tls_psk, psk, (int)max_psk_len);
	if (len < 0) return 0;
	return (unsigned int)len;
}
#endif

static int net__try_connect_tcp(const char *host, uint16_t port, mosq_sock_t *sock, const char *bind_address, bool blocking)
{
	struct addrinfo hints;
	struct addrinfo *ainfo, *rp;
	struct addrinfo *ainfo_bind, *rp_bind;
	int s;
	int rc = MOSQ_ERR_SUCCESS;

	ainfo_bind = NULL;
	BTraceIn

	*sock = INVALID_SOCKET;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	s = getaddrinfo(host, NULL, &hints, &ainfo);
	if(s){
		errno = s;
		return MOSQ_ERR_EAI;
	}

	if(bind_address){
		s = getaddrinfo(bind_address, NULL, &hints, &ainfo_bind);
		if(s){
			freeaddrinfo(ainfo);
			errno = s;
			return MOSQ_ERR_EAI;
		}
	}

	for(rp = ainfo; rp != NULL; rp = rp->ai_next){
		BLog("essaie ainfo %p", rp);
		*sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if(*sock == INVALID_SOCKET) 
		{BLog("if(*sock == INVALID_SOCKET) ");
			continue;
		}

		if(rp->ai_family == AF_INET){
			((struct sockaddr_in *)rp->ai_addr)->sin_port = htons(port);
			BLog("AF_INET");
		}else if(rp->ai_family == AF_INET6){
			((struct sockaddr_in6 *)rp->ai_addr)->sin6_port = htons(port);
			BLog("AF_INET6");
		}else{
			BLog("else COMPAT_CLOSE");
			COMPAT_CLOSE(*sock);
			*sock = INVALID_SOCKET;
			continue;
		}

		if(bind_address){  // Benoit: Passe pas ici
			BLog("pas ici");
			for(rp_bind = ainfo_bind; rp_bind != NULL; rp_bind = rp_bind->ai_next){
				if(bind(*sock, rp_bind->ai_addr, rp_bind->ai_addrlen) == 0){
					break;
				}
			}
			if(!rp_bind){
				COMPAT_CLOSE(*sock);
				*sock = INVALID_SOCKET;
				continue;
			}
		}

		if(!blocking){
			/* Set non-blocking */
			if(net__socket_nonblock(sock)){
				BLog(" non-blocking");
				continue;
			}
		}

		rc = connect(*sock, rp->ai_addr, rp->ai_addrlen);
		if(rc == 0 || errno == EINPROGRESS || errno == COMPAT_EWOULDBLOCK){
			if(rc < 0 && (errno == EINPROGRESS || errno == COMPAT_EWOULDBLOCK)){
				rc = MOSQ_ERR_CONN_PENDING;
			}

			if(blocking){
				/* Set non-blocking */
				BLog("Force to know Blocking");
				if(net__socket_nonblock(sock)){
					continue;
				}
			}
			BLog("On quitte");
			break;
		}
		BLog("Suivant");
		COMPAT_CLOSE(*sock);
		*sock = INVALID_SOCKET;
	}
	freeaddrinfo(ainfo);
	if(bind_address){
		freeaddrinfo(ainfo_bind);
	}
	if(!rp){
		BLog("if(!rp) on n'a pas passé a travers tous les rp");
		return MOSQ_ERR_ERRNO;
	}
	BTraceOut
	return rc;
}


#ifdef WITH_UNIX_SOCKETS
static int net__try_connect_unix(const char *host, mosq_sock_t *sock)
{
	struct sockaddr_un addr;
	int s;
	int rc;

	if(host == NULL || strlen(host) == 0 || strlen(host) > sizeof(addr.sun_path)-1){
		return MOSQ_ERR_INVAL;
	}

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, host, sizeof(addr.sun_path)-1);

	s = socket(AF_UNIX, SOCK_STREAM, 0);
	if(s < 0){
		return MOSQ_ERR_ERRNO;
	}
	rc = net__socket_nonblock(&s);
	if(rc) return rc;

	rc = connect(s, (struct sockaddr *)&addr, sizeof(struct sockaddr_un));
	if(rc < 0){
		close(s);
		return MOSQ_ERR_ERRNO;
	}
	printf("Benoit: On a notre socket, %02x:%02x\n", (int)addr.sun_path[0],(int)addr.sun_path[1]);
	*sock = s;

	return 0;
}
#endif


static int net__try_connect(const char *host, uint16_t port, mosq_sock_t *sock, const char *bind_address, bool blocking)
{
	if(port == 0){
#ifdef WITH_UNIX_SOCKETS
	BLog("WITH_UNIX_SOCKETS host %s, port = %d", host, port);

		return net__try_connect_unix(host, sock);
#else
		return MOSQ_ERR_NOT_SUPPORTED;
#endif
	}else{
	BLog("ICI NO WITH_UNIX_SOCKETS host %s, port = %d", host, port);
		return net__try_connect_tcp(host, port, sock, bind_address, blocking);
	}
}

static void net__print_ssl_error(struct mosquitto *mosq)
{
	char ebuf[256];
	unsigned long e;
	int num = 0;

	e = ERR_get_error();
	while(e){
		log__printf(mosq, MOSQ_LOG_ERR, "OpenSSL Error[%d]: %s", num, ERR_error_string(e, ebuf));
		BLog("OpenSSL Error[%d]: %s", num, ERR_error_string(e, ebuf));
		e = ERR_get_error();
		num++;
	}
}

// INFO:Benoit voir loop.c aussi appeler de la
int net__socket_connect_tls(struct mosquitto *mosq)
{
	int ret, err;
	long res;

	ERR_clear_error();
	if (mosq->tls_ocsp_required) {
		/* Note: OCSP is available in all currently supported OpenSSL versions. */
		if ((res=SSL_set_tlsext_status_type(mosq->ssl, TLSEXT_STATUSTYPE_ocsp)) != 1) {
			log__printf(mosq, MOSQ_LOG_ERR, "Could not activate OCSP (error: %ld)", res);
			return MOSQ_ERR_OCSP;
		}
		if ((res=SSL_CTX_set_tlsext_status_cb(mosq->ssl_ctx, mosquitto__verify_ocsp_status_cb)) != 1) {
			log__printf(mosq, MOSQ_LOG_ERR, "Could not activate OCSP (error: %ld)", res);
			return MOSQ_ERR_OCSP;
		}
		if ((res=SSL_CTX_set_tlsext_status_arg(mosq->ssl_ctx, mosq)) != 1) {
			log__printf(mosq, MOSQ_LOG_ERR, "Could not activate OCSP (error: %ld)", res);
			return MOSQ_ERR_OCSP;
		}
	}

	ret = SSL_connect(mosq->ssl);
	if(ret != 1) {
		err = SSL_get_error(mosq->ssl, ret);
		if (err == SSL_ERROR_SYSCALL) {
			mosq->want_connect = true;
			BLog("mosq->want_connect = true; SSL_ERROR_SYSCALL");
			return MOSQ_ERR_SUCCESS;
		}
		if(err == SSL_ERROR_WANT_READ){
			mosq->want_connect = true;
			BLog("mosq->want_connect = true; SSL_ERROR_WANT_READ");
			/* We always try to read anyway */
		}else if(err == SSL_ERROR_WANT_WRITE){
			mosq->want_write = true;
			mosq->want_connect = true;
			BLog("mosq->want_connect = true; SSL_ERROR_WANT_WRITE");
		}else{
			net__print_ssl_error(mosq);

			COMPAT_CLOSE(mosq->sock);
			mosq->sock = INVALID_SOCKET;
			net__print_ssl_error(mosq);BLog("MOSQ_ERR_TLS");
			return MOSQ_ERR_TLS;
		}
	}else{
			BLog("mosq->want_connect = false;");
		mosq->want_connect = false;
	}
	BLog("net__socket_connect_tls return");
	return MOSQ_ERR_SUCCESS;
}

static int net__tls_load_ca(struct mosquitto *mosq)
{
	int ret;

	if(mosq->tls_use_os_certs){
		SSL_CTX_set_default_verify_paths(mosq->ssl_ctx);
	}
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	if(mosq->tls_cafile || mosq->tls_capath){
		ret = SSL_CTX_load_verify_locations(mosq->ssl_ctx, mosq->tls_cafile, mosq->tls_capath);
		if(ret == 0){
			if(mosq->tls_cafile && mosq->tls_capath){
				BLog("Error: Unable to load CA certificates, check bridge_cafile \"%s\" and bridge_capath \"%s\".", mosq->tls_cafile, mosq->tls_capath);
				log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load CA certificates, check cafile \"%s\" and capath \"%s\".", mosq->tls_cafile, mosq->tls_capath);
			}else if(mosq->tls_cafile){
				BLog("Error: Unable to load CA certificates, check bridge_cafile \"%s\".", mosq->tls_cafile);
				log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load CA certificates, check cafile \"%s\".", mosq->tls_cafile);
			}else{
				BLog("Error: Unable to load CA certificates, check bridge_capath \"%s\".", mosq->tls_capath);
				log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load CA certificates, check capath \"%s\".", mosq->tls_capath);
			}
BLog("MOSQ_ERR_TLS");
			return MOSQ_ERR_TLS;
		}
	}
#else
	if(mosq->tls_cafile){
		ret = SSL_CTX_load_verify_file(mosq->ssl_ctx, mosq->tls_cafile);
		if(ret == 0){
#  ifdef WITH_BROKER
			log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load CA certificates, check bridge_cafile \"%s\".", mosq->tls_cafile);
#  else
			log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load CA certificates, check cafile \"%s\".", mosq->tls_cafile);
#  endif
BLog("MOSQ_ERR_TLS");
			return MOSQ_ERR_TLS;
		}
	}
	if(mosq->tls_capath){
		ret = SSL_CTX_load_verify_dir(mosq->ssl_ctx, mosq->tls_capath);
		if(ret == 0){
#  ifdef WITH_BROKER
			log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load CA certificates, check bridge_capath \"%s\".", mosq->tls_capath);
#  else
			log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load CA certificates, check capath \"%s\".", mosq->tls_capath);
#  endif
BLog("MOSQ_ERR_TLS");
			return MOSQ_ERR_TLS;
		}
	}
#endif
	return MOSQ_ERR_SUCCESS;
}


static int net__init_ssl_ctx(struct mosquitto *mosq)
{
	int ret;
	uint8_t tls_alpn_wire[256];
	uint8_t tls_alpn_len;
	static int compteur = 0;
	BTraceIn
	BLog("compteur = %d\n", compteur++);

	if(mosq->user_ssl_ctx){
		BLog("mosq->user_ssl_ctx est non-nul");
		mosq->ssl_ctx = mosq->user_ssl_ctx;
		if(!mosq->ssl_ctx_defaults){
			BLog("ICI: net__init_ssl_ctx, compteur = %d", compteur++);
			return MOSQ_ERR_SUCCESS;
		}else if(!mosq->tls_cafile && !mosq->tls_capath && !mosq->tls_psk){
			BLog("ICI: net__init_ssl_ctx, compteur = %d", compteur++);
			log__printf(mosq, MOSQ_LOG_ERR, "Error: If you use MOSQ_OPT_SSL_CTX then MOSQ_OPT_SSL_CTX_WITH_DEFAULTS must be true, or at least one of cafile, capath or psk must be specified.");
			return MOSQ_ERR_INVAL;
		}
	}

	/* Apply default SSL_CTX settings. This is only used if MOSQ_OPT_SSL_CTX
	 * has not been set, or if both of MOSQ_OPT_SSL_CTX and
	 * MOSQ_OPT_SSL_CTX_WITH_DEFAULTS are set. */
	if(mosq->tls_cafile || mosq->tls_capath || mosq->tls_psk || mosq->tls_use_os_certs){
		BLog("On est à la bonne place");
		if(!mosq->ssl_ctx){
			BLog("On initialise le ctx c'est bien");
			net__init_tls();

#if OPENSSL_VERSION_NUMBER < 0x10100000L
			mosq->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
#else
			BLog("opensll version > 0x10100000");
			mosq->ssl_ctx = SSL_CTX_new(TLS_client_method());
#endif

			if(!mosq->ssl_ctx){
				log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to create TLS context.");
BLog("MOSQ_ERR_TLS");
				net__print_ssl_error(mosq);
				return MOSQ_ERR_TLS;
			}
		}

#ifdef SSL_OP_NO_TLSv1_3
//#error "SSL_OP_NO_TLSv1_3 est défini"
		if(mosq->tls_psk){
			SSL_CTX_set_options(mosq->ssl_ctx, SSL_OP_NO_TLSv1_3);
		}
#endif

		if(!mosq->tls_version){
			SSL_CTX_set_options(mosq->ssl_ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1);
#ifdef SSL_OP_NO_TLSv1_3
		}else if(!strcmp(mosq->tls_version, "tlsv1.3")){
			SSL_CTX_set_options(mosq->ssl_ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2);
#endif
		}else if(!strcmp(mosq->tls_version, "tlsv1.2")){
			SSL_CTX_set_options(mosq->ssl_ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
		}else if(!strcmp(mosq->tls_version, "tlsv1.1")){
			SSL_CTX_set_options(mosq->ssl_ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1);
		}else{
			log__printf(mosq, MOSQ_LOG_ERR, "Error: Protocol %s not supported.", mosq->tls_version);
			return MOSQ_ERR_INVAL;
		}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		/* Allow use of DHE ciphers */
		SSL_CTX_set_dh_auto(mosq->ssl_ctx, 1);
#endif
		/* Disable compression */
		SSL_CTX_set_options(mosq->ssl_ctx, SSL_OP_NO_COMPRESSION);

		/* Set ALPN */
		if(mosq->tls_alpn) {
			tls_alpn_len = (uint8_t) strnlen(mosq->tls_alpn, 254);
			tls_alpn_wire[0] = tls_alpn_len;  /* first byte is length of string */
			memcpy(tls_alpn_wire + 1, mosq->tls_alpn, tls_alpn_len);
			SSL_CTX_set_alpn_protos(mosq->ssl_ctx, tls_alpn_wire, tls_alpn_len + 1U);
		}

#ifdef SSL_MODE_RELEASE_BUFFERS
//#error "SSL_MODE_RELEASE_BUFFERS est défini"
			/* Use even less memory per SSL connection. */
			SSL_CTX_set_mode(mosq->ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
#endif


		if(mosq->tls_ciphers){
			BLog("if(mosq->tls_ciphers) VRAI");
			ret = SSL_CTX_set_cipher_list(mosq->ssl_ctx, mosq->tls_ciphers);
			if(ret == 0){
				log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to set TLS ciphers. Check cipher list \"%s\".", mosq->tls_ciphers);
				net__print_ssl_error(mosq);
BLog("MOSQ_ERR_TLS");
				return MOSQ_ERR_TLS;
			}
		}
		if(mosq->tls_cafile || mosq->tls_capath || mosq->tls_use_os_certs){
			BLog("if(mosq->tls_cafile || mosq->tls_capath || mosq->tls_use_os_certs)");
			ret = net__tls_load_ca(mosq);
			if(ret != MOSQ_ERR_SUCCESS){
				net__print_ssl_error(mosq);
BLog("MOSQ_ERR_TLS");
				return MOSQ_ERR_TLS;
			}
			if(mosq->tls_cert_reqs == 0){
				SSL_CTX_set_verify(mosq->ssl_ctx, SSL_VERIFY_NONE, NULL);
			}else{
				SSL_CTX_set_verify(mosq->ssl_ctx, SSL_VERIFY_PEER, mosquitto__server_certificate_verify);
			}

			if(mosq->tls_pw_callback){
				SSL_CTX_set_default_passwd_cb(mosq->ssl_ctx, mosq->tls_pw_callback);
				SSL_CTX_set_default_passwd_cb_userdata(mosq->ssl_ctx, mosq);
			}

			if(mosq->tls_certfile){
				ret = SSL_CTX_use_certificate_chain_file(mosq->ssl_ctx, mosq->tls_certfile);
				if(ret != 1){
					log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load client certificate \"%s\".", mosq->tls_certfile);
					net__print_ssl_error(mosq);
BLog("MOSQ_ERR_TLS");
					return MOSQ_ERR_TLS;
				}
			}
			if(mosq->tls_keyfile){
					printf("Benoit: 1000: mosq->tls_keyfile \n");

				if(mosq->tls_keyform == mosq_k_engine){
					printf("Benoit: 1001: (mosq->tls_keyform == mosq_k_engine) \n");
				}else{
					printf("Benoit: 1003: FAUX (mosq->tls_keyform == mosq_k_engine) \n");
					ret = SSL_CTX_use_PrivateKey_file(mosq->ssl_ctx, mosq->tls_keyfile, SSL_FILETYPE_PEM);
					if(ret != 1){
						log__printf(mosq, MOSQ_LOG_ERR, "Error: Unable to load client key file \"%s\".", mosq->tls_keyfile);
						net__print_ssl_error(mosq);
BLog("MOSQ_ERR_TLS");
						return MOSQ_ERR_TLS;
					}
				}
				ret = SSL_CTX_check_private_key(mosq->ssl_ctx);
				if(ret != 1){
					log__printf(mosq, MOSQ_LOG_ERR, "Error: Client certificate/key are inconsistent.");
					net__print_ssl_error(mosq);
BLog("MOSQ_ERR_TLS");
					return MOSQ_ERR_TLS;
				}
			}
#ifdef FINAL_WITH_TLS_PSK
// #error FINAL_WITH_TLS_PSK est defini
BLog("#ifdef FINAL_WITH_TLS_PSK");
		}else if(mosq->tls_psk){
			SSL_CTX_set_psk_client_callback(mosq->ssl_ctx, psk_client_callback);
			if(mosq->tls_ciphers == NULL){
				SSL_CTX_set_cipher_list(mosq->ssl_ctx, "PSK");
			}
#endif
		}
	}

	return MOSQ_ERR_SUCCESS;
}



int net__socket_connect_step3(struct mosquitto *mosq, const char *host)
{
	BIO *bio;
	BTraceIn
	int rc = net__init_ssl_ctx(mosq);
	if(rc){
		net__socket_close(mosq);
		return rc;
	}

	if(mosq->ssl_ctx){
		if(mosq->ssl){
			SSL_free(mosq->ssl);
		}
		mosq->ssl = SSL_new(mosq->ssl_ctx);
		if(!mosq->ssl){
			net__socket_close(mosq);
			net__print_ssl_error(mosq);
			BLog("MOSQ_ERR_TLS");
			return MOSQ_ERR_TLS;
		}

		SSL_set_ex_data(mosq->ssl, tls_ex_index_mosq, mosq);
		bio = BIO_new_socket(mosq->sock, BIO_NOCLOSE);
		if(!bio){
			net__socket_close(mosq);
			net__print_ssl_error(mosq);
			BLog("MOSQ_ERR_TLS");
			return MOSQ_ERR_TLS;
		}
		SSL_set_bio(mosq->ssl, bio, bio);

		/*
		 * required for the SNI resolving
		 */
		if(SSL_set_tlsext_host_name(mosq->ssl, host) != 1) {
			net__socket_close(mosq);
			BLog("MOSQ_ERR_TLS");
			return MOSQ_ERR_TLS;
		}
		do {
			if(net__socket_connect_tls(mosq)){
				net__socket_close(mosq);
				BLog("MOSQ_ERR_TLS");
				return MOSQ_ERR_TLS;
			}
			if (mosq->want_connect == false)
				break;
			sleep(1);
		} while (1);
	}
	BTraceOut
	return MOSQ_ERR_SUCCESS;
}

/* Create a socket and connect it to 'ip' on port 'port'.  */
int net__socket_connect(struct mosquitto *mosq, const char *host, uint16_t port, const char *bind_address, bool blocking)
{
	int rc, rc2;
	BTraceIn
	if(!mosq || !host) return MOSQ_ERR_INVAL;
	BLog(" host %s", host);

	rc = net__try_connect(host, port, &mosq->sock, bind_address, blocking);  // Benoit: Ici on a une trace de wireshark.
	if(rc > 0) return rc;

	BLog("net__socket_connect %d", mosq->tcp_nodelay);
	if(mosq->tcp_nodelay){
		BLog("PAS ICI: mosq->tcp_nodelay %s\n", host);
		int flag = 1;
		if(setsockopt(mosq->sock, IPPROTO_TCP, TCP_NODELAY, (const void*)&flag, sizeof(int)) != 0){
			log__printf(mosq, MOSQ_LOG_WARNING, "Warning: Unable to set TCP_NODELAY.");
		}
	}

	if(!mosq->socks5_host)
	{
		BLog("ICI: vers net__socket_connect_step3 %s\n", host);
		rc2 = net__socket_connect_step3(mosq, host);
		if(rc2) return rc2;
	}
	BTraceOut
	return rc;
}

static int net__handle_ssl(struct mosquitto* mosq, int ret)
{
	int err;
	BTraceIn
	err = SSL_get_error(mosq->ssl, ret);
	if (err == SSL_ERROR_WANT_READ) {
		BLog("READ");
		ret = -1;
		errno = EAGAIN;
	}
	else if (err == SSL_ERROR_WANT_WRITE) {
		BLog("WRITE");
		ret = -1;
		mosq->want_write = true;
		errno = EAGAIN;
	}
	else {
		BLog("ELSE");
		net__print_ssl_error(mosq);
		errno = EPROTO;
	}
	ERR_clear_error();

	return ret;
}

ssize_t net__read(struct mosquitto *mosq, void *buf, size_t count)
{
	BTraceIn
	int ret;
	assert(mosq);
	errno = 0;
	if(mosq->ssl){
		ret = SSL_read(mosq->ssl, buf, (int)count);
		if(ret <= 0){
			ret = net__handle_ssl(mosq, ret);
		}
		return (ssize_t )ret;
	}else{
		/* Call normal read/recv */
		return read(mosq->sock, buf, count);
	}
}

ssize_t net__write(struct mosquitto *mosq, const void *buf, size_t count)
{
	int ret;
	assert(mosq);
	BTraceIn
	errno = 0;
	if(mosq->ssl){

		mosq->want_write = false;
		ret = SSL_write(mosq->ssl, buf, (int)count);
		if(ret < 0){

			ret = net__handle_ssl(mosq, ret);
		}
		return (ssize_t )ret;
	}else{
		/* Call normal write/send */
		return write(mosq->sock, buf, count);
	}
}


int net__socket_nonblock(mosq_sock_t *sock)
{
	int opt;
	/* Set non-blocking */
	BTraceIn
	opt = fcntl(*sock, F_GETFL, 0);
	if(opt == -1){
		COMPAT_CLOSE(*sock);
		*sock = INVALID_SOCKET;
		return MOSQ_ERR_ERRNO;
	}
	if(fcntl(*sock, F_SETFL, opt | O_NONBLOCK) == -1){
		/* If either fcntl fails, don't want to allow this client to connect. */
		COMPAT_CLOSE(*sock);
		*sock = INVALID_SOCKET;
		return MOSQ_ERR_ERRNO;
	}
	return MOSQ_ERR_SUCCESS;
}


int net__socketpair(mosq_sock_t *pairR, mosq_sock_t *pairW)
{
	BTraceIn
	int sv[2];

	*pairR = INVALID_SOCKET;
	*pairW = INVALID_SOCKET;
#if BEN_SUPPRIME_PAIR
	if(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1){
		return MOSQ_ERR_ERRNO;
	}
	if(net__socket_nonblock(&sv[0])){
		COMPAT_CLOSE(sv[1]);
		return MOSQ_ERR_ERRNO;
	}
	if(net__socket_nonblock(&sv[1])){
		COMPAT_CLOSE(sv[0]);
		return MOSQ_ERR_ERRNO;
	}
	*pairR = sv[0];
	*pairW = sv[1];
#endif // #if BEN_SUPPRIME_PAIR

	return MOSQ_ERR_SUCCESS;
}

