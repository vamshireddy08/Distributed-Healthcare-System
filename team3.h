/* team3.h - all functions in this header */
#include<errno.h>	//to know errors types while creating sockets
#include<unistd.h> 	//to close file descriptor
#include<signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include<sys/signal.h>
#include<sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>

#include<stdlib.h>    //atoi()
#include<string.h>
#include<stdbool.h>
#include <stdio.h>    //printf()

#ifndef	INADDR_NONE
#define	INADDR_NONE	0xffffffff
#endif	/* INADDR_NONE */


/*     headers for aes encryption  	*/

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>

#define UID ""
#define PWD ""
#define domain ""

extern int errno;

/*------------------------------------------------------------------------
 * connectsock - allocate & connect a socket using TCP or UDP
 *------------------------------------------------------------------------
 */
int
connectsock(const char *host, const char *service, const char *transport )
/*
 * Arguments:
 *      host      - name of host to which connection is desired
 *      service   - service associated with the desired port
 *      transport - name of transport protocol to use ("tcp" or "udp")
 */
{
	struct hostent	*phe;	/* pointer to host information entry	*/
	struct servent	*pse;	/* pointer to service information entry	*/
	struct protoent *ppe;	/* pointer to protocol information entry*/
	struct sockaddr_in sin;	/* an Internet endpoint address		*/
	int	s, type;	/* socket descriptor and socket type	*/

/*

 // filling socket address data structure

	struct sockaddr_in server_address;

	server_address.sin_family=AF_INET;
	server_address.sin_port=htons(portnumber);
	server_address.sin_addr.s_addr=htonl(INADDR_ANY); //any local ip address of local machine




*/
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;

    /* Map service name to port number */
	if ( pse = getservbyname(service, transport) )
		sin.sin_port = htons(pse->s_port);
	else if ((sin.sin_port=htons((unsigned short)atoi(service))) == 0)
		perror("can't get service");

    /* Map host name to IP address, allowing for dotted decimal */
	if ( phe = gethostbyname(host) )
		memcpy(&sin.sin_addr, phe->h_addr, phe->h_length);
	else if ( (sin.sin_addr.s_addr = inet_addr(host)) == INADDR_NONE )
		perror("can't get  host entry\n");

    /* Map transport protocol name to protocol number */
	if ( (ppe = getprotobyname(transport)) == 0)
		perror("can't get  protocol entry\n");

    /* Use protocol to choose a socket type */
	if (strcmp(transport, "udp") == 0)
		type = SOCK_DGRAM;
	else
		type = SOCK_STREAM;

    /* Allocate a socket */
	s = socket(PF_INET, type, ppe->p_proto);
	if (s < 0)
		perror("can't create socket\n");

    /* Connect the socket */
	if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) < 0)
		perror("can't connect to server \n");
	return s;
}


int	connectTCP(const char *host, const char *service )
/*
 * Arguments:
 *      host    - name of host to which connection is desired
 *      service - service associated with the desired port
 */
{
	return connectsock( host, service, "tcp");

}


int passivesock(const char *service, const char *transport, int qlen){
/* create a passive socket for use in server */
	struct servent *pse;	//pointer to service information
	struct protoent *ppe;	//pointer to protocol information
	struct sockaddr_in sin;	//structure variable for internet endpoint address
	int s,type;

	memset(&sin,0,sizeof(sin));


	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr= INADDR_ANY;


	/*Map servie name to port number*/

	if(pse = getservbyname(service,transport))
			sin.sin_port = htons(ntohs((unsigned short)pse->s_port));
	else if ((sin.sin_port=htons((unsigned short)atoi(service))) == 0)
			perror("Can't get a service entry\n");

	/*Map protocol name to protocol number*/
	if((ppe = getprotobyname(transport)) == 0)
			perror("Can't get a  protocol entry\n");

	/*Use protocol to choose a socket type*/

		if (strcmp(transport,"udp") == 0)
					type = SOCK_DGRAM;
		else
					type = SOCK_STREAM;

		/*Allocate a socket*/

		s= socket(AF_INET, type, 0);
		if(s<0)
				perror("Can't create socket: \n");

	  /*Bind the socket*/
		if(bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0)
				perror("Can't bind to port: \n");

		if(type == SOCK_STREAM && listen(s,qlen) < 0)
					perror("Can't listen on port: \n");

		return s;


}


int passiveTCP(const char *service, int qlen)
{
/* service associated with the desired port */
return passivesock(service,"tcp",qlen);
}




int encrypt(unsigned char *plaintext, int plaintext_len, const unsigned char *aad,
            int aad_len, const unsigned char *key, const unsigned char *iv,
            unsigned char *ciphertext, unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, ciphertext_len = 0;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    /* Set IV length if default 12 bytes (96 bits) is not appropriate */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
		handleErrors();

    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(aad && aad_len > 0)
    {
        if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
            handleErrors();
    }

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(plaintext)
    {
        if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
            handleErrors();

        ciphertext_len = len;
    }

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
		handleErrors();
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        handleErrors();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, const unsigned char *aad,
            int aad_len, unsigned char *tag, const unsigned char *key,  const unsigned char *iv,
            unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, plaintext_len = 0, ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
		handleErrors();

    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(aad && aad_len > 0)
    {
        if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
            handleErrors();
    }

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(ciphertext)
    {
        if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
            handleErrors();

        plaintext_len = len;
    }

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        handleErrors();

    /* Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0)
    {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    }
    else
    {
        /* Verify failed */
        return -1;
    }
}

void handleErrors(void)
{
    unsigned long errCode;

    printf("An error occurred\n");
    while(errCode = ERR_get_error())
    {
        char *err = ERR_error_string(errCode, NULL);
        printf("%s\n", err);
    }
    abort();
}
