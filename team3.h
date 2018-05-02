/* team3.h - all functions in this header */
#include<errno.h>	//to know errors types while creating sockets
#include<unistd.h> 	//to close file descriptor
#include<signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <pwd.h>		//to get password without displaying it while typing it

#include<sys/signal.h>
#include<sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>

#include<stdlib.h>    //atoi()
#include<string.h>
#include<stdbool.h>
#include <stdio.h>    //printf()
#include<limits.h>
#include <time.h>
#include <stdio_ext.h>

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

void gen_username(int user_input, char* string_name)
{
 string_name[100]="USR_";
	    FILE *fptr;
 		 char ch[5];
		int number=0;
		char *a="PU_";//Patient
		char *b="DU_";//Doctor
		char *c="AU_";//Admin	
		char snum[10];	
		char NumberToFile[5];
		char chr[5];	
		char *filename;			

		switch(user_input)
		{
				case 2: strcpy(string_name,a);
						filename="p.txt";	
						break;
				case 4: strcpy(string_name,b);
						filename="d.txt";	
						break;
				case 6: strcpy(string_name,c);
						filename="a.txt";		
						break;
				default:strcpy(string_name,a);
					filename="p.txt";
					break;

		}

		//sprintf(filename, "%c.txt");
   		fptr=fopen(filename,"r");
		    if (fptr == NULL)
			{
				printf("Cannot open file \n");
				exit(0);
			}
			fgets(ch,sizeof(ch),fptr);
			fclose(fptr);
		number=atoi(ch);
		number=number+1;	
		fptr=fopen(filename,"w");//Opening file again to update the value.
		    if (fptr == NULL)
			{
				printf("Cannot open file \n");
				exit(0);
			}
			snprintf(chr, sizeof(chr),"%04d",number);		
			fprintf(fptr,"%s",chr);
			fclose(fptr);
		snprintf(snum, sizeof(snum),"%s",ch);//IMPORTANT		
		strcat(string_name,snum);	
}

int captcha( )
{
int size=7;

char str[8],buffer[8];
     srand(time(0));
    const char charset[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (size) {
            --size;
            for (size_t n = 0; n < size; n++) {
                        int key = rand() % (int) (sizeof charset - 1);
                        str[n] = charset[key];
                    }
            str[size] = '\0';
        }
    
printf("Enter captcha : %s\n", str );
__fpurge(stdin);         //function to clear I/O buffer
fgets(buffer,7,stdin);
buffer[strcspn(buffer, "\n")] = 0;
if (! strcmp(str,buffer))
    return 0; 
else
    return 1;
}
