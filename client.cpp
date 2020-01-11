#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <WinSock2.h>
#include <stdio.h>

#pragma warning(disable:4996)

int main(int argc, char* argv[])
{
	// ssl init
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

	// Using TLSv1_2 method
	const SSL_METHOD* method = TLSv1_2_method();
	SSL_CTX* ctx = SSL_CTX_new(method);
	if (!ctx)
	{
		fprintf(stderr, "[!] TLSv1_2_method(), SSL_CTX_new()\n");
		return -1;
	}

	// Socket Init
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData))
	{
		fprintf(stderr, "[!] WSAStartup()\n");
		return -1;
	}

	// Socket Open
	SOCKET socket_client = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (socket_client == INVALID_SOCKET)
	{
		fprintf(stderr, "[!] WSASocket()\n");
		return -1;
	}

	// Port Open
	struct sockaddr_in sa_server = { 0 };
	sa_server.sin_family = AF_INET;
	sa_server.sin_addr.s_addr = inet_addr("192.168.42.2");
	sa_server.sin_port = htons(4433);	// Test TLS Server Port is '4433'

	// Connection
	int errchk = connect(socket_client, (struct sockaddr*) & sa_server, sizeof(sa_server));
	if (errchk == SOCKET_ERROR)
	{
		fprintf(stderr, "[!] connect()\n");
		return -1;
	}

	// SSL Init
	SSL* ssl = SSL_new(ctx);
	if (!ssl)
	{
		fprintf(stderr, "[!] SSL_new()\n");
		return -1;
	}

	// SSL Connection 
	SSL_set_fd(ssl, socket_client);
	errchk = SSL_connect(ssl);
	if (errchk < 0)
	{
		fprintf(stderr, "[!] SSL_accept()\n");
		return -1;
	}
	printf("SSL Connection using %s\n", SSL_get_cipher(ssl));

	// Get Server Certification Information
	X509* cert_server = SSL_get_peer_certificate(ssl);
	if (cert_server != NULL)
	{
		printf("Server Certification : \n");
		printf("\t subject : %s\n", X509_NAME_oneline(X509_get_subject_name(cert_server), 0, 0));
		printf("\t issuer : %s\n", X509_NAME_oneline(X509_get_issuer_name(cert_server), 0, 0));
	}
	else printf("Server dose not have Certification\n");
	X509_free(cert_server);

	// Read Test
	char buf[2500] = { 0 };
	errchk = SSL_read(ssl, buf, sizeof(buf) - 1);
	buf[errchk] = '\0';
	printf("[!] Server : %s\n", buf);

	SSL_shutdown(ssl);
	closesocket(socket_client);
	SSL_free(ssl);
	SSL_CTX_free(ctx);

	return 0;
}