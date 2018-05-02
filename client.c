/* client.c */
/* default ip: ipv6 localhost    port number: 3000 */
#include "team3.h"
#define BLEN 1024


void  __fpurge(FILE *stream);

static const unsigned char key[] = "01234567890123456789012345678901";  //256 bit key
static const unsigned char iv[] = "0123456789012345"; //128 bit IV
    /* Some additional data to be authenticated */
static const unsigned char aad[] = "Some AAD data";
    /* Buffer for the tag */
unsigned char tag[16];
int decryptedtext_len = 0, ciphertext_len = 0;
char ciphertext[1024];

static inline void send_to(int my_socket,char* buffer)
{
    bzero(ciphertext,BLEN);
 /* Encrypt the plaintext */
    ciphertext_len = encrypt(buffer, strlen(buffer), aad, strlen(aad), key, iv, ciphertext, tag);
      send(my_socket, &ciphertext,BLEN,0);        //sending number to server
}

static inline void recv_from(int my_socket, char* buffer)
{
    bzero(ciphertext,BLEN);
      recv(my_socket, &ciphertext,BLEN,0);    //receiving response from the server
    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt(ciphertext, strlen(ciphertext), aad, strlen(aad), tag, key, iv, buffer);//receiving response from the server
}
int my_socket;
void sigintHandler(int sig_num)
{

    printf("\n terminated using Ctrl+C \n");
    fflush(stdout);
	close(my_socket);
	exit(1);
}
int main( int argc , char* argv[]  )
{
signal(SIGINT, sigintHandler);
int  portno, n;
struct sockaddr_in6 serv_addr;
struct hostent *server;

portno = 3000;

//Sockets Layer Call: socket()
my_socket = socket(AF_INET6, SOCK_STREAM, 0);
if (my_socket < 0)
    perror("ERROR opening socket");


server = gethostbyname2("::1",AF_INET6);


if (server == NULL) {
    fprintf(stderr, "ERROR, no such host\n");
    exit(0);
}

memset((char *) &serv_addr, 0, sizeof(serv_addr));
serv_addr.sin6_flowinfo = 0;
serv_addr.sin6_family = AF_INET6;
memmove((char *) &serv_addr.sin6_addr.s6_addr, (char *) server->h_addr, server->h_length);
serv_addr.sin6_port = htons(portno);

//Sockets Layer Call: connect()
if (connect(my_socket, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
    perror("ERROR connecting");

      int logged=0;  //to check if user logged in or not
      char buffer[BLEN];
        int user_option=0;
        char *display;
      OpenSSL_add_all_algorithms();
      ERR_load_crypto_strings();


start:  user_option=0;

            printf("\nenter 1 to patient login 2 to patient signup\n");
            printf("enter 3 to doctor  login 4 to doctor  signup\n");
            printf("enter 5 to company login 6 to company signup\n");
            printf("enter 7 to exit, signup if you are new user \n");
            __fpurge(stdin);
      if( scanf("%d",&user_option) !=1)
            {
                printf("enter only given options\n");
                goto start;
            }
    sprintf(buffer,"%d",user_option);
      bzero(ciphertext,BLEN);
    /* Encrypt the plaintext */
    ciphertext_len = encrypt(buffer, strlen(buffer), aad, strlen(aad), key, iv, ciphertext, tag);
      send(my_socket, &ciphertext,BLEN,0);

switch( user_option )
{
case 3:     bzero(buffer,BLEN);
           printf("enter username: ");
           __fpurge(stdin);         //function to clear I/O buffer
           fgets(buffer,BLEN,stdin);
           buffer[strcspn(buffer, "\n")] = 0;
           send_to(my_socket,buffer);

    bzero(buffer,BLEN);
  	strncpy(buffer, getpass("Password: "), 80);
    send_to(my_socket,buffer);    //sending number to server
while(    captcha())
{
printf("please enter correct captcha\n");
}

    bzero(buffer,BLEN);
    recv_from(my_socket, buffer);

    if(strcmp(buffer,"match")==0)
    {    printf("you are logged in \n");
    logged=2;
    }
    else {
    printf("server response: %s\n\n",buffer);
    goto start;
    }
    break;



case 5:
case 1:       bzero(buffer,BLEN);
           printf("enter username: ");
           __fpurge(stdin);         //function to clear I/O buffer
           fgets(buffer,BLEN,stdin);
           buffer[strcspn(buffer, "\n")] = 0;
           send_to(my_socket,buffer);

    bzero(buffer,BLEN);
strncpy(buffer, getpass("Password: "), 80);
    send_to(my_socket,buffer);    //sending number to server
while( captcha())
{
printf("please enter correct captcha\n");
}

    bzero(buffer,BLEN);
    recv_from(my_socket, buffer);

    if(strcmp(buffer,"match")==0)
    {    printf("you are logged in \n");
    logged=1;
    }
    else {
    printf("server response: %s\n\n",buffer);
    goto start;
    }
    break;

case 4:

   bzero(buffer,BLEN);
	gen_username( user_option,  buffer);	//automatically generate username for doctor
    printf("your username: |%s|\n",buffer);
    buffer[strcspn(buffer, "\n")] = 0;
    send_to(my_socket,buffer);        //sending username to server

    bzero(buffer,BLEN);
    printf("enter password: ");
    __fpurge(stdin);
    fgets(buffer,BLEN,stdin);
    buffer[strcspn(buffer, "\n")] = 0;
    send_to(my_socket,buffer);    //sending password to server

    bzero(buffer,BLEN);
    printf("enter name: ");
    __fpurge(stdin);
    fgets(buffer,BLEN,stdin);
    buffer[strcspn(buffer, "\n")] = 0;
    send_to(my_socket,buffer);        //sending first name to server

    bzero(buffer,BLEN);
    printf("enter mobile: ");
    __fpurge(stdin);
    fgets(buffer,BLEN,stdin);
    buffer[strcspn(buffer, "\n")] = 0;
    send_to(my_socket,buffer);        //sending last name to server

    bzero(buffer,BLEN);
    printf("enter address: ");
    __fpurge(stdin);
    fgets(buffer,BLEN,stdin);
    buffer[strcspn(buffer, "\n")] = 0;
    send_to(my_socket,buffer);        //sending date of birth to server

    bzero(buffer,BLEN);
    printf("enter Specality: ");
    __fpurge(stdin);
    fgets(buffer,BLEN,stdin);
    buffer[strcspn(buffer, "\n")] = 0;
    send_to(my_socket,buffer);        //sending gender to server

    bzero(buffer,BLEN);
    printf("enter network1: ");
    __fpurge(stdin);
    fgets(buffer,BLEN,stdin);
    buffer[strcspn(buffer, "\n")] = 0;
    send_to(my_socket,buffer);        //sending mobile number to server

    bzero(buffer,BLEN);
    printf("enter network2: ");
    __fpurge(stdin);
    fgets(buffer,BLEN,stdin);
    buffer[strcspn(buffer, "\n")] = 0;
    send_to(my_socket,buffer);        //sending address to server

    bzero(buffer,BLEN);
    printf("enter Network3: ");
    __fpurge(stdin);
    fgets(buffer,BLEN,stdin);
    buffer[strcspn(buffer, "\n")] = 0;
    send_to(my_socket,buffer);        //sending gmail to server

    bzero(buffer,BLEN);
    recv_from(my_socket, buffer);

    printf("server response: %s\n\n",buffer);
    goto start;
    break;

case 6:
case 2:
bzero(buffer,BLEN);
gen_username( user_option,  buffer);

    printf("your username: |%s|\n",buffer);
    buffer[strcspn(buffer, "\n")] = 0;
    send_to(my_socket,buffer);        //sending username to server

    bzero(buffer,BLEN);
    printf("enter password: ");
    __fpurge(stdin);
    fgets(buffer,BLEN,stdin);
    buffer[strcspn(buffer, "\n")] = 0;

    send_to(my_socket,buffer);    //sending password to server

    bzero(buffer,BLEN);
    printf("enter first name: ");
    __fpurge(stdin);
    fgets(buffer,BLEN,stdin);
    buffer[strcspn(buffer, "\n")] = 0;

    send_to(my_socket,buffer);        //sending first name to server

    bzero(buffer,BLEN);
    printf("enter last name: ");
    __fpurge(stdin);
    fgets(buffer,BLEN,stdin);
    buffer[strcspn(buffer, "\n")] = 0;

    send_to(my_socket,buffer);        //sending last name to server

    bzero(buffer,BLEN);
    printf("enter date of birth in yyyy-mm-dd format: ");
    __fpurge(stdin);
    fgets(buffer,BLEN,stdin);
    buffer[strcspn(buffer, "\n")] = 0;

    send_to(my_socket,buffer);        //sending date of birth to server

    bzero(buffer,BLEN);
    printf("enter Gender M/F: ");
    __fpurge(stdin);
    fgets(buffer,BLEN,stdin);
    buffer[strcspn(buffer, "\n")] = 0;

    send_to(my_socket,buffer);        //sending gender to server

    bzero(buffer,BLEN);
    printf("enter mobile: ");
    __fpurge(stdin);
    fgets(buffer,BLEN,stdin);
    buffer[strcspn(buffer, "\n")] = 0;

    send_to(my_socket,buffer);        //sending mobile number to server

    bzero(buffer,BLEN);
    printf("enter address: ");
    __fpurge(stdin);
    fgets(buffer,BLEN,stdin);
    buffer[strcspn(buffer, "\n")] = 0;

    send_to(my_socket,buffer);        //sending address to server

    bzero(buffer,BLEN);
    printf("enter gmail: ");
    __fpurge(stdin);
    fgets(buffer,BLEN,stdin);
    buffer[strcspn(buffer, "\n")] = 0;

    send_to(my_socket,buffer);        //sending gmail to server

    bzero(buffer,BLEN);
    recv_from(my_socket, buffer);

    printf("server response: %s\n\n",buffer);
    goto start;
    break;
case 7: goto end;

default: printf("invalid input\n");
            goto start;
}//switch

while(logged==1)
{
select:
    printf("\nenter 11 to view personal details\n");
    printf("enter 12 to book appointment\n");
    printf("enter 13 to view medical history\n");
    printf("enter 15 to cancel appointment\n");
    printf("enter 14 to logout\n");

user_option=0;
bzero(buffer,BLEN);
if( scanf("%d",&user_option) !=1)
{
    printf("\n\n enter only integers from given options \n\n");
    goto select;
}
sprintf(buffer,"%d",user_option);
    send_to(my_socket,buffer);

switch(user_option){
case 15:   printf("your upcoming appointments\n");   //to view medical history
stayinloop:    bzero(buffer,BLEN);
            recv_from(my_socket,buffer);
            if( strcmp(buffer,"cmd_end") != 0 )
            {
                display=(char *)malloc(sizeof(char)*32);

                strncpy(display,buffer,32);
                printf("patient name: %-32s\n",display);
                strncpy(display,buffer+32,32);
                printf("doctor name : %-32s\n",display);
                strncpy(display,buffer+64,32);
                printf("date        : %-32s\n",display);
                strncpy(display,buffer+96,32);
                printf("time        : %-32s\n",display);
                strncpy(display,buffer+128,32);
                printf("location    : %-32s\n",display);
                strncpy(display,buffer+160,32);
                printf("service     : %-32s\n",display);
                strncpy(display,buffer+192,32);
                printf("comments    : %-32s\n",display);
                bzero(display,sizeof(display));
                strncpy(display,buffer+224,32);
                printf("id          : %-32s\n",display);
                free(display);
                goto stayinloop;
            }
    ha:     printf("\n enter id of appointment you want to cancel \n");
            if( scanf("%d",&user_option) !=1)
            {
                printf("\n\n enter only integers from given options \n\n");
                goto ha;
            }
            sprintf(buffer,"%d",user_option);
                send_to(my_socket,buffer);
                printf("id |%s|\n",buffer);
            break;
case 11: bzero(buffer,BLEN);
    recv_from(my_socket,buffer);

    printf("my details\n");

    display=(char *)malloc(sizeof(char)*32);
    strncpy(display,buffer,32);
    printf("first name: %-32s\n",display);
    strncpy(display,buffer+32,32);
    printf("last name : %-32s\n",display);
    strncpy(display,buffer+64,32);
    printf("contact   : %-32s\n",display);
    strncpy(display,buffer+96,32);
    printf("address   : %-32s\n",display);
    strncpy(display,buffer+128,32);
    printf("gmail     : %-32s\n",display);
    free(display);

    goto select;
    break;
case 12:printf("\nAvailable Appointments\n\n");
stayinloop1:    bzero(buffer,BLEN);
    recv_from(my_socket,buffer);
if( strcmp(buffer,"cmd_end") != 0 )
{
    display=(char *)malloc(sizeof(char)*32);

strncpy(display,buffer,32);
    printf("\nDoctor name: %-32s\n",display);
strncpy(display,buffer+32,32);
    printf("date       : %-32s\n",display);
strncpy(display,buffer+64,32);
    printf("time       : %-32s\n",display);
strncpy(display,buffer+96,32);
    printf("location   : %-32s\n",display);
strncpy(display,buffer+128,32);
    printf("service    : %-32s\n",display);
strncpy(display,buffer+160,32);
    printf("network    : %-32s\n",display);
  strncpy(display,buffer+192,32);
    printf("id    : %-32s\n",display);
    free(display);
    goto stayinloop1;
}
else
{
    bzero(buffer,BLEN);
        s1:       printf("\nenter id: ");
               __fpurge(stdin);         //function to clear I/O buffer
               if( scanf("%d",&user_option) !=1)
               {
                   printf("enter integer from given options\n");
                   goto s1;
               }
               sprintf(buffer,"%d",user_option);
               printf("buffer: |%s|\n",buffer);
               buffer[strcspn(buffer, "\n")] = 0;

               send_to(my_socket,buffer);   //send id for booking appointment
               bzero(buffer,BLEN);
               recv_from(my_socket,buffer);
               printf("|%s|\n",buffer);

    goto select;
}    break;

case 13:
        printf("medical history\n");   //to view medical history
        stayinloop111:    bzero(buffer,BLEN);
                    recv_from(my_socket,buffer);
                    if( strcmp(buffer,"cmd_end") != 0 )
                    {
                        display=(char *)malloc(sizeof(char)*32);

                        strncpy(display,buffer,32);
                        printf("\npatient name: %-32s\n",display);
                        strncpy(display,buffer+32,32);
                        printf("doctor name : %-32s\n",display);
                        strncpy(display,buffer+64,32);
                        printf("date        : %-32s\n",display);
                        strncpy(display,buffer+96,32);
                        printf("time        : %-32s\n",display);
                        strncpy(display,buffer+128,32);
                        printf("location    : %-32s\n",display);
                        strncpy(display,buffer+160,32);
                        printf("service     : %-32s\n",display);
                        strncpy(display,buffer+192,32);
                        printf("comments    : %-32s\n\n",display);
                        free(display);
                        goto stayinloop111;
                    }
                    else
                        goto select;
        break;
case 14:
    printf("logging out\n");
    goto start;
    break;
default: goto select;
    break;
}//switch
}//while logged =1

while(logged==2)
{
    select2:
        printf("\nenter 20 to view personal details\n");
        printf("enter 21 to register\n");
        printf("enter 22 to view medical history\n");
        printf("enter 23 to logout\n");

    user_option=0;
    bzero(buffer,BLEN);
    if( scanf("%d",&user_option) !=1)
    {
        printf("\n\n enter only integers from given options \n\n");
        goto select2;
    }
    sprintf(buffer,"%d",user_option);
        send_to(my_socket,buffer);
switch(user_option)
{
    case 23:
           printf("logging out\n");
           goto start;
           break;
     case 22:
            printf("medical history\n");   //to view medical history
            stayinloop2:    bzero(buffer,BLEN);
                        recv_from(my_socket,buffer);
                            if( strcmp(buffer,"cmd_end") != 0 )
                            {
                                 display=(char *)malloc(sizeof(char)*32);
                                 strncpy(display,buffer,32);
                                 printf("patient name: %-32s\n",display);
                                 strncpy(display,buffer+32,32);
                                 printf("doctor name : %-32s\n",display);
                                 strncpy(display,buffer+64,32);
                                 printf("date        : %-32s\n",display);
                                 strncpy(display,buffer+96,32);
                                 printf("time        : %-32s\n",display);
                                 strncpy(display,buffer+128,32);
                                 printf("location    : %-32s\n",display);
                                 strncpy(display,buffer+160,32);
                                 printf("service     : %-32s\n",display);
                                 strncpy(display,buffer+192,32);
                                 printf("comments    : %-32s\n",display);
                                 free(display);
                                 goto stayinloop2;
                             }
                             else
                                 goto select2;
                                                      break;
        case 20: bzero(buffer,BLEN);
                  recv_from(my_socket,buffer);
                     printf("my details\n");

                        display=(char *)malloc(sizeof(char)*32);
                        strncpy(display,buffer,32);
            printf("doctor name: %-32s\n",display);
            strncpy(display,buffer+32,32);
            printf("mobile : %-32s\n",display);
            strncpy(display,buffer+64,32);
            printf("address   : %-32s\n",display);
            strncpy(display,buffer+96,32);
            printf("specality   : %-32s\n",display);
            free(display);
            goto select2;

    case 21:    //register an appointment
               bzero(buffer,BLEN);
               printf("enter date in yyyy-mm-dd format: ");
               __fpurge(stdin);         //function to clear I/O buffer
               fgets(buffer,BLEN,stdin);
               buffer[strcspn(buffer, "\n")] = 0;
               send_to(my_socket,buffer);

               bzero(buffer,BLEN);
               printf("enter time in hh-mm-ss format: ");
               __fpurge(stdin);         //function to clear I/O buffer
               fgets(buffer,BLEN,stdin);
               buffer[strcspn(buffer, "\n")] = 0;
               send_to(my_socket,buffer);
               bzero(buffer,BLEN);
                        recv_from(my_socket,buffer);
                           printf("%s\n",buffer);

    default: user_option= 0;
                goto select2;
                break;
}//switch end
}//while logged=2

end:     close(my_socket);
    printf("exiting program\n");
    /* Remove error strings */
        ERR_free_strings();
return 0;
}//main
