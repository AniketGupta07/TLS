#include <bits/stdc++.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
 
#define FAIL    -1

using namespace std; 
 
 
// Create the SSL socket and intialize the socket address structure
int OpenListener(int port){
	int server_fd;
	struct sockaddr_in address;
	int opt=1;
	// int addrlen=
	server_fd=socket(AF_INET,SOCK_STREAM,0);
	if (server_fd==0)
	{
		perror("socket failed");
		exit(EXIT_FAILURE);
	}
	address.sin_family=AF_INET;
	address.sin_addr.s_addr=INADDR_ANY;
	address.sin_port=htons(port);
	if (bind(server_fd,(struct sockaddr *)&address,sizeof(address))<0)
	{
		perror("bind failed");
		exit(EXIT_FAILURE);
	}
	if(listen(server_fd,3)<0){
		perror("can't listen");
		exit(EXIT_FAILURE);
	}
	return server_fd;
}
 

SSL_CTX* InitServerCTX(void)
{   const SSL_METHOD *method;
    SSL_CTX *ctx;
 
    method = TLS_server_method();  /* create new server-method instance */
    ctx = SSL_CTX_new(method);   /* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}
 
void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;
 
    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}
 
void Servlet(SSL* ssl){
	char buf[1024]={0};
	int sd,bytes;
	 if ( SSL_accept(ssl) == -1 )     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else
    {
    	while(1){
			bytes=SSL_read(ssl,buf,sizeof(buf));

			buf[bytes]='\0';
			string str=buf;
			if(str=="q")break;
			cout<<"Client Message: "<<buf<<std::endl;
			
			string msg;
        	
        	cout<<"Type your Message:"<<endl;
	        cin>>msg;
	        int n=msg.length();
	        char arr[n+1];
	        strcpy(arr,msg.c_str());
	        // if(msg=="q")break;
	        SSL_write(ssl,arr,strlen(arr));
	        
			// SSL_write(ssl,arr,strlen(arr));
			
		}
		sd=SSL_get_fd(ssl);
		SSL_free(ssl);
		close(sd);
	}
} 

int main(int argc, char *argv[])
{
	SSL_CTX* ctx;	
	int server_fd;
	char *portnum;
	portnum = argv[1];
	// ctx=InitServerCTX()
	// ch
	// struct sockaddr_in address;
	ctx=InitServerCTX();
	LoadCertificates(ctx,"mycert.pem","mycert.pem");
	server_fd = OpenListener(atoi(portnum));
	 while (1)
    {   struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;
 		fork();
        int client = accept(server_fd, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
        // printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);              /* get new SSL state with context */
        SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
        Servlet(ssl);         /* service connection */
    }
	close(server_fd);
	SSL_CTX_free(ctx);
	return 0;
}
