#include <bits/stdc++.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>
#include<unistd.h>

#include <errno.h>

#include <malloc.h>

#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#define PORT 6669
 #define FAIL    -1
using namespace std;
int Open_Connection(){
	// struct sockaddr_in address;
    int sock = 0;
    struct sockaddr_in serv_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Socket creation error \n");
        return -1;
    }

    memset(&serv_addr, '0', sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0)
    {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("\nConnection Failed \n");
        return -1;
    }
    return sock;

}

void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    long a = SSL_get_verify_result(ssl);
    if(a==X509_V_OK){
      cout<<"OK";
    }
    else{
      cout<<"Invalid"<<endl;
      cout<<a<<" and "<<X509_V_OK<<endl;
    }
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No client certificates configured.\n");
}
SSL_CTX* InitCTX(void){
	const SSL_METHOD* meth;
	SSL_CTX* ctx;
	// SSL_load_error_strings();
	// OpenSSL_add_ssl_algorithms();
	meth=TLS_client_method();
	ctx=SSL_CTX_new(meth);
	if ( ctx == NULL ){
        ERR_print_errors_fp(stderr);
        abort();
    }
	return ctx;
}

int main(int argc, char const *argv[])
{

	SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char buf[1024];
	char acClientRequest[1024] ={0};
    int bytes;

    // if(! SSL_CTX_load_verify_locations(ctx, "~/Summer/TLS/certs/cacert.pem", NULL)){
    //   cout<<"Failed";
    // }
    ctx = InitCTX();
    long a = SSL_CTX_load_verify_locations(ctx,NULL,"~/Summer/TLS/certs");
    if (! a) {
      cout<<"couldn't load certs";
    }
    else{
      cout<<"Certificate successfully loaded"<<a;
    }
    server = Open_Connection();
    ssl = SSL_new(ctx);      /* create new SSL connection state */

    SSL_set_fd(ssl, server);    /* attach the socket descriptor */
    if ( SSL_connect(ssl) == FAIL )
    {  /* perform the connection */
       printf("Connection Failed\n");
        ERR_print_errors_fp(stderr);
    }else
    {

        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);
        // cout<<"yo"<<endl;
        while(1){
        	string msg;
        	char buf[1024];
        	cout<<"Type your Message:(q to exit)"<<endl;
	        cin>>msg;
	        int n=msg.length();
	        char arr[n+1];
	        strcpy(arr,msg.c_str());
	        // if(msg=="q")break;
	        SSL_write(ssl,arr,strlen(arr));
	        if(msg=="q")break;
			bytes=SSL_read(ssl,buf,sizeof(buf));
			cout<<"Server msg: "<<string(buf,bytes)<<std::endl;
		}
			SSL_free(ssl);
	// }
}

	close(server);
	// send(sock,"hello from client",strlen("hello from client"),0);
	// int valread=read(sock,buffer,1024);
	SSL_CTX_free(ctx);
	// printf("%s\n",buf);
	return 0;
}
