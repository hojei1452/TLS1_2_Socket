#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <WinSock2.h>
#include <stdio.h>

#pragma warning(disable:4996)

int main(int argc, char* argv[])
{
	// init
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

	// Using TLSv1_2
	const SSL_METHOD* method = TLSv1_2_method();
	SSL_CTX* ctx = SSL_CTX_new(method);
	if (!ctx)
	{
		fprintf(stderr, "[!] TLSv1_2_method(), SSL_CTX_new()\n");
		return -1;
	}

	// Certificate Set
	if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0)
	{
		fprintf(stderr, "[!] SSL_CTX_use_certificate_file()\n");
		return -1;
	}

	// Private Key Set
	if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0)
	{
		fprintf(stderr, "[!] SSL_CTX_use_certificate_file()\n");
		return -1;
	}

	// Private Key Check
	if (!SSL_CTX_check_private_key(ctx))
	{
		fprintf(stderr, "[!] SSL_CTX_check_private_key()\n");
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
	SOCKET socket_server = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (socket_server == INVALID_SOCKET)
	{
		fprintf(stderr, "[!] WSASocket()\n");
		return -1;
	}

	// Port Open
	struct sockaddr_in sa_server = { 0 };
	sa_server.sin_family = AF_INET;
	sa_server.sin_addr.s_addr = htonl(INADDR_ANY);
	sa_server.sin_port = htons(4433);	// Test TLS Server Port is '4433'

	int errchk = bind(socket_server, (struct sockaddr*) & sa_server, sizeof(sa_server));
	if (errchk == SOCKET_ERROR)
	{
		fprintf(stderr, "[!] bind()\n");
		return -1;
	}

	// Port Listening
	errchk = listen(socket_server, 5);
	if (errchk)
	{
		fprintf(stderr, "[!] listen()\n");
		return -1;
	}

	for (;;)
	{
		// Connect Client
		struct sockaddr_in sa_client = { 0 };
		int len_client = sizeof(sa_client);

		SOCKET socket_client = accept(socket_server, (struct sockaddr*) & sa_client, &len_client);
		if (socket_client == INVALID_SOCKET)
		{
			fprintf(stderr, "[!] accept()\n");
			return -1;
		}
		printf("\nConnection from %s, port %d\n", inet_ntoa(sa_client.sin_addr), ntohs(sa_client.sin_port));
		//closesocket(socket_server);

		// SSL Init
		SSL* ssl = SSL_new(ctx);
		if (!ssl)
		{
			fprintf(stderr, "[!] SSL_new()\n");
			return -1;
		}

		// SSL Connection 
		SSL_set_fd(ssl, socket_client);
		errchk = SSL_accept(ssl);
		if (errchk < 0)
		{
			fprintf(stderr, "[!] SSL_accept()\n");
			return -1;
		}
		printf("SSL Connection using %s\n", SSL_get_cipher(ssl));

		// Get Client Certification Information
		X509* cert_client = SSL_get_peer_certificate(ssl);
		if (cert_client != NULL)
		{
			printf("Client Certification : \n");
			printf("\t subject : %s\n", X509_NAME_oneline(X509_get_subject_name(cert_client), 0, 0));
			printf("\t issuer : %s\n", X509_NAME_oneline(X509_get_issuer_name(cert_client), 0, 0));
		}
		else printf("Client dose not have Certification\n");
		X509_free(cert_client);

		// Send Tets
		const char* test = "Server!";
		errchk = SSL_write(ssl, test, strlen(test));

		/*SSL_shutdown(ssl);
		closesocket(socket_client);
		SSL_free(ssl);
		SSL_CTX_free(ctx);*/
	}
	return 0;
}