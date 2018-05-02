
#include<pthread.h>
#include "team3.h"
#include<mysql/mysql.h>	//mysql.h is in usr/include/mysql

//global variables to connect to database

static char* host="localhost";
static char* user="cmpe207";
static char* password="Cmpe@207";
static char* dbname="cmpe207";

unsigned int port=3306;	//mysql database server is listening on this port

static char* unix_socket=NULL;	//to specify connection type

unsigned int flag = 0;	//connection odbc

/* Set up the key and iv. Do I need to say to not hard code these in a real application? :-) */

    /* A 256 bit key */
    static const unsigned char key[] = "01234567890123456789012345678901";

    /* A 128 bit IV */
    static const unsigned char iv[] = "0123456789012345";

    /* Some additional data to be authenticated */
    static const unsigned char aad[] = "Some AAD data";

    /* Buffer for the tag */
    unsigned char tag[16];

    int decryptedtext_len = 0, ciphertext_len = 0;

#define BLEN 1024
#define qlen 2

int TCP_thread(int client_socket);
void TCP_multithread(int server_socket);

struct { pthread_mutex_t mutex_lock; } lock;

char ciphertext[BLEN];
static inline void send_to(int client_socket,char* buffer)
{
	bzero(ciphertext,BLEN);
 /* Encrypt the plaintext */
    ciphertext_len = encrypt(buffer, strlen(buffer), aad, strlen(aad), key, iv, ciphertext, tag);
	send(client_socket, &ciphertext,BLEN,0);

}
static inline void recv_from(int client_socket, char* buffer)
{
	bzero(ciphertext,BLEN);
int n=recv(client_socket, &ciphertext,BLEN,0);	//receiving response from the server
if(n<0)
	perror("recevive: ");
else
	/* Decrypt the ciphertext */
    decryptedtext_len = decrypt(ciphertext, strlen(ciphertext), aad, strlen(aad), tag, key, iv, buffer);

}


int main( int argc , char* argv[ ] ){

int sockfd, portno=3000;
struct sockaddr_in6 serv_addr,cli_addr ;
socklen_t clilen;
char client_addr_ipv6[100];
clilen = sizeof(cli_addr);


//Sockets Layer Call: socket()
sockfd = socket(AF_INET6, SOCK_STREAM, 0);
if (sockfd < 0)
    error("ERROR opening socket");

bzero((char *) &serv_addr, sizeof(serv_addr));

serv_addr.sin6_flowinfo = 0;
serv_addr.sin6_family = AF_INET6;
serv_addr.sin6_addr = in6addr_any;
serv_addr.sin6_port = htons(portno);
int on=1;
int r= setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
if (r)
{
    printf("ipv6 error at line 89\n");
    exit(1);
}
//Sockets Layer Call: bind()
if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
    error("ERROR on binding");

//Sockets Layer Call: listen()
listen(sockfd, 5);


printf("TCP multithread server is running\n");
pthread_t thread1;
int client_socket;
while (1)
    {
        client_socket = accept(sockfd,    (struct sockaddr *) &cli_addr, &clilen);
        if (client_socket < 0)
        {
            if (errno == EINTR)
            perror("accept");
        continue;
        }
        inet_ntop(AF_INET6, &(cli_addr.sin6_addr),client_addr_ipv6, 100);

printf("Incoming connection from client having IPv6 address: |%s|\n",client_addr_ipv6);
printf("Client port is %d\n", ntohs(cli_addr.sin6_port));

    if (pthread_create( &thread1 , NULL ,(void *) &TCP_thread,(void *) client_socket) < 0)    //don't use &client socket it will not run properly
            perror("pthread_create");
    }

printf("closing main\n");
close(sockfd);    //close the socket connection, removes socket descriptor from table.
return 0;
}


int TCP_thread(int client_socket)
{
/* encryption initialization functions */
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

/* sql initialization functions */
MYSQL *connection;
connection=mysql_init(NULL);	//initialize the mysql structure
int i;
 if ( !(mysql_real_connect(connection,host,user,password,dbname,port,unix_socket,flag) ) )
	{
		fprintf(stderr , "\n Error: %s [%d]\n", mysql_error(connection), mysql_errno(connection) );
		exit(1);
	}
else
	printf("connection is successful\n");

MYSQL_RES *result;	// variable to results from db query
MYSQL_ROW *row;
  	char query[BLEN];
  	char username[32];
        char buffer[BLEN];

int logged=0;
    	pthread_t thId = pthread_self();
    	printf("i'm in thread %lu\n",thId);
main:
while(logged==0){
	bzero(buffer,BLEN);
   	recv_from(client_socket, buffer);
	int user_option=atoi(buffer);

	switch(user_option)
	{
            case 3:bzero(buffer,BLEN);
            recv_from(client_socket, buffer);

            bzero(username,32);
            strncpy(username,buffer,strlen(buffer)+1);

            bzero(buffer,BLEN);
            recv_from(client_socket, buffer);

            char* password;
            password=(char * )malloc(sizeof(char)*strlen(buffer));
            strncpy(password,buffer,strlen(buffer)+1);

            char* password2;
            password2= (char *)malloc (sizeof(char)*32);
            bzero(query,BLEN);
            strcpy(query,"SELECT d_password FROM t4 where d_username= \'" );
            strncat(query,username,strlen(username));
            strcat(query,"\'");

            if (mysql_query(connection, query)) 	//function to request data from db
            {
                printf("MYSQL ERROR: %s\n", mysql_error(connection));
            }

            result=mysql_store_result(connection);	//variable to store results and display
            if(result==NULL)
                printf("no username\n");

                if( mysql_num_rows(result) == 0)
                    strcpy(buffer,"invalid username");
                    else{
                        while(row = mysql_fetch_row(result))	//iterates from 1st to last row
                            {
                                if(row[0]==NULL)
                                    strcpy (password2,"null");
                                else
                                    strcpy(password2,row[0]);

                            }
                            mysql_free_result(result);
                            bzero(buffer,BLEN);
                            if(strcmp(password2,password)==0)
                            {
                                strcpy(buffer,"match");
                                logged=2;
                            }
                            else
                                strcpy(buffer,"wrong password");
                            }

send_to(client_socket,buffer);

free(password2);
free(password);
if(logged==0)
    goto main;
break;
case 1://user login
	bzero(buffer,BLEN);
   	recv_from(client_socket, buffer);
	bzero(username,32);
	strncpy(username,buffer,strlen(buffer)+1);

	bzero(buffer,BLEN);
   	recv_from(client_socket, buffer);
	//char* password;
	password=(char * )malloc(sizeof(char)*strlen(buffer));
	strncpy(password,buffer,strlen(buffer)+1);

	//char* password2;
	password2= (char *)malloc (sizeof(char)*32);
	bzero(query,BLEN);
	strcpy(query,"SELECT  password FROM t1 where p_username= \'" );
	strncat(query,username,strlen(username));
	strcat(query,"\'");

	if (mysql_query(connection, query)) 	//function to request data from db
                {
                    printf("MYSQL ERROR: %s\n", mysql_error(connection));
                }


	result=mysql_store_result(connection);	//variable to store results and display
	if(result==NULL)
		printf("no username\n");

	if( mysql_num_rows(result) == 0)
		strcpy(buffer,"invalid username");
	else{
		while(row = mysql_fetch_row(result))	//iterates from 1st to last row
		{
			if(row[0]==NULL)
				strcpy (password2,"null");

			else
				strcpy(password2,row[0]);

		}
		mysql_free_result(result);
		bzero(buffer,BLEN);
		if(strcmp(password2,password)==0)
			{	strcpy(buffer,"match");
				logged=1;	}
		else
			strcpy(buffer,"wrong password");
		}

	send_to(client_socket,buffer);

	free(password2);
	free(password);
	if(logged==0)
		goto main;
	break;

case 2: //user signup

	bzero(buffer,BLEN);
   	recv_from(client_socket, buffer);

	bzero(username,32);
	strncpy(username,buffer,strlen(buffer)+1);

		bzero(buffer,BLEN);
   	recv_from(client_socket, buffer);

	//char* password;
	password=(char * )malloc(sizeof(char)*strlen(buffer));
	strncpy(password,buffer,strlen(buffer)+1);

		bzero(buffer,BLEN);
   	recv_from(client_socket, buffer);

	char* firstname;
	firstname=(char * )malloc(sizeof(char)*strlen(buffer));
	strncpy(firstname,buffer,strlen(buffer)+1);

		bzero(buffer,BLEN);
   	recv_from(client_socket, buffer);

	char* lastname;
	lastname=(char * )malloc(sizeof(char)*strlen(buffer));
	strncpy(lastname,buffer,strlen(buffer)+1);

		      bzero(buffer,BLEN);
   	          recv_from(client_socket, buffer);
	          char* date_of_birth;
	          date_of_birth=(char * )malloc(sizeof(char)*strlen(buffer));
	          strncpy(date_of_birth,buffer,strlen(buffer)+1);

		bzero(buffer,BLEN);
   	    recv_from(client_socket, buffer);
	       char* gender;
	          gender=(char * )malloc(sizeof(char)*strlen(buffer));
	             strncpy(gender,buffer,strlen(buffer)+1);

	bzero(buffer,BLEN);
   	recv_from(client_socket, buffer);

	char* mobile;
	mobile=(char * )malloc(sizeof(char)*strlen(buffer));
	strncpy(mobile,buffer,strlen(buffer)+1);

	bzero(buffer,BLEN);
   	recv_from(client_socket, buffer);

	char* address;
	address=(char * )malloc(sizeof(char)*strlen(buffer));
	strncpy(address,buffer,strlen(buffer)+1);

	bzero(buffer,BLEN);
   	recv_from(client_socket, buffer);

	char* gmail;
	gmail=(char * )malloc(sizeof(char)*strlen(buffer));
	strncpy(gmail,buffer,strlen(buffer)+1);

	bzero(query,BLEN);
	strcpy(query, "INSERT INTO t1 (p_username,password,first_name,last_name,DOB,sex,mobile, address,gmail) VALUES (\'");
    strncat(query,username,strlen(username));
    strcat(query,"\',\'");
    strncat(query,password,strlen(password));
    strcat(query,"\',\'");
    strncat(query,firstname,strlen(firstname));
    strcat(query,"\',\'");
    strncat(query,lastname,strlen(lastname));
    strcat(query,"\',\'");
    strncat(query,date_of_birth,strlen(date_of_birth));	//we can't encrypt date
    strcat(query,"\',\'");
    strncat(query,gender,strlen(gender));
    strcat(query,"\',\'");
    strncat(query,mobile,strlen(mobile));
    strcat(query,"\',\'");
    strncat(query,address,strlen(address));
    strcat(query,"\',\'");
    strncat(query,gmail,strlen(gmail));
    strcat(query,"\')");

    bzero(buffer,BLEN);

    if (mysql_query(connection, query)) 	//function to request data from db
        {
            sprintf(buffer,"MYSQL ERROR: %s\n", mysql_error(connection));
            printf("MYSQL ERROR: %s\n", mysql_error(connection));
        }
    else
	   strcpy(buffer,"signup completed!");

	send_to(client_socket,buffer);

free(password);
free(firstname);
free(lastname);
free(date_of_birth);
free(gender);
free(mobile);
free(address);
free(gmail);
goto main;



case 4:
bzero(buffer,BLEN);
recv_from(client_socket, buffer);
bzero(username,32);
strncpy(username,buffer,strlen(buffer)+1);  //doctor username

    bzero(buffer,BLEN);
recv_from(client_socket, buffer);

//char* password;
password=(char * )malloc(sizeof(char)*strlen(buffer));
strncpy(password,buffer,strlen(buffer)+1);

    bzero(buffer,BLEN);
recv_from(client_socket, buffer);

char* name;
name=(char * )malloc(sizeof(char)*strlen(buffer));
strncpy(name,buffer,strlen(buffer)+1);

    bzero(buffer,BLEN);
recv_from(client_socket, buffer);

//char* mobile;
mobile=(char * )malloc(sizeof(char)*strlen(buffer));
strncpy(mobile,buffer,strlen(buffer)+1);

    bzero(buffer,BLEN);
recv_from(client_socket, buffer);

//char* address;
address=(char * )malloc(sizeof(char)*strlen(buffer));
strncpy(address,buffer,strlen(buffer)+1);

    bzero(buffer,BLEN);
recv_from(client_socket, buffer);

char* specality;
specality=(char * )malloc(sizeof(char)*strlen(buffer));
strncpy(specality,buffer,strlen(buffer)+1);

bzero(buffer,BLEN);
recv_from(client_socket, buffer);

char* network1;
network1=(char * )malloc(sizeof(char)*strlen(buffer));
strncpy(network1,buffer,strlen(buffer)+1);

bzero(buffer,BLEN);
recv_from(client_socket, buffer);

char* network2;
network2=(char * )malloc(sizeof(char)*strlen(buffer));
strncpy(network2,buffer,strlen(buffer)+1);

bzero(buffer,BLEN);
recv_from(client_socket, buffer);

char* network3;
network3=(char * )malloc(sizeof(char)*strlen(buffer));
strncpy(network3,buffer,strlen(buffer)+1);

bzero(query,BLEN);
strcpy(query, "INSERT INTO t4 (d_username,d_password,d_name,d_mobile,d_address,specality,network1,network2,network3) VALUES (\'");
strncat(query,username,strlen(username));
strcat(query,"\',\'");
strncat(query,password,strlen(password));
strcat(query,"\',\'");
strncat(query,name,strlen(name));
strcat(query,"\',\'");
strncat(query,mobile,strlen(mobile));
strcat(query,"\',\'");
strncat(query,address,strlen(address));
strcat(query,"\',\'");
strncat(query,specality,strlen(specality));
strcat(query,"\',\'");
strncat(query,network1,strlen(network1));
strcat(query,"\',\'");
strncat(query,network2,strlen(network2));
strcat(query,"\',\'");
strncat(query,network3,strlen(network3));
strcat(query,"\')");

bzero(buffer,BLEN);

if (mysql_query(connection, query)) 	//function to request data from db
    {
        sprintf(buffer,"MYSQL ERROR: %s\n", mysql_error(connection));
        printf("MYSQL ERROR: %s\n", mysql_error(connection));
    }
else
   strcpy(buffer,"signup completed!");

send_to(client_socket,buffer);

free(password);
free(firstname);
free(lastname);
free(date_of_birth);
free(gender);
free(mobile);
free(address);
free(gmail);
goto main;
break;
default:
        goto end;
}//end of switch
}//while logged=0

while(logged==1)
{
half:	bzero(buffer,BLEN);
   	    recv_from(client_socket, buffer);

	int user_option=atoi(buffer);
switch(user_option)
{
case 15:
        bzero(buffer,BLEN);
	       strcpy(query,"SELECT p_name,d_name,date,time,location,service,comments,id FROM t3 WHERE p_username=\'");
	          strncat(query,username,strlen(username));
	             strcat(query,"\'");
		if (mysql_query(connection, query)) 	//function to request data from db
                {sprintf(buffer,"MYSQL ERROR: %s\n", mysql_error(connection));
                    printf("MYSQL ERROR: %s\n", mysql_error(connection));
                }

	               result=mysql_store_result(connection);	//variable to store results and display
	unsigned int  col=mysql_num_fields(result);

while(row = mysql_fetch_row(result))	//iterates from 1st to last row
{
	for(i=0;i<col;i++)
	{
	sprintf(buffer+(32*i),"%-32s",row[i]);
	}
send_to(client_socket,buffer);
}
bzero(buffer,BLEN);
strcpy(buffer,"cmd_end");
send_to(client_socket,buffer);
	mysql_free_result(result);
    bzero(buffer,BLEN);
   	recv_from(client_socket, buffer);
    bzero(query,BLEN);
    sprintf(query," INSERT INTO t2 (id,d_username,d_name,date,time,location,service) SELECT id,d_username,d_name,date,time,location,service FROM t3 WHERE id=%s",buffer);

    if (mysql_query(connection, query)) 	//function to request data from db
                {
                    printf("MYSQL ERROR: %s\n", mysql_error(connection));
                }
                result=mysql_store_result(connection);
                mysql_free_result(result);
    bzero(query,BLEN);
    sprintf(query," DELETE FROM t3 WHERE id=%s",buffer);
    if (mysql_query(connection, query)) 	//function to request data from db
                            {
                                printf("MYSQL ERROR: %s\n", mysql_error(connection));
                            }
                            result=mysql_store_result(connection);
                            mysql_free_result(result);
    bzero(query,BLEN);
    sprintf(query," UPDATE t2 SET p_username='NULL' WHERE id=%s",buffer);
    if (mysql_query(connection, query)) 	//function to request data from db
                            {
                                printf("MYSQL ERROR: %s\n", mysql_error(connection));
                            }
                            result=mysql_store_result(connection);
                            mysql_free_result(result);

// sql queries for deleting appointments
    goto half;

case 14: printf("logging out\n");
	logged=0;
	goto main;
	break;
case 11: bzero(buffer,BLEN);
	strcpy(query,"SELECT first_name,last_name,mobile,address,gmail FROM t1 WHERE p_username=\'");
	strncat(query,username,strlen(username));
	strcat(query,"\'");
		if (mysql_query(connection, query)) 	//function to request data from db
                {sprintf(buffer,"MYSQL ERROR: %s\n", mysql_error(connection));
                    printf("MYSQL ERROR: %s\n", mysql_error(connection));
                }

	result=mysql_store_result(connection);	//variable to store results and display
	/*unsigned int*/ col=mysql_num_fields(result);

while(row = mysql_fetch_row(result))	//iterates from 1st to last row
{
	for(i=0;i<col;i++)
	{
	sprintf(buffer+32*i,"%-32s",row[i]);
	}
}
	mysql_free_result(result);
	send_to(client_socket,buffer);
	goto half;

case 13: bzero(buffer,BLEN);
	strcpy(query,"SELECT p_name,d_name,date,time,location,service,comments FROM t3 WHERE p_username=\'");
	strncat(query,username,strlen(username));
	strcat(query,"\'");
		if (mysql_query(connection, query)) 	//function to request data from db
                {sprintf(buffer,"MYSQL ERROR: %s\n", mysql_error(connection));
                    printf("MYSQL ERROR: %s\n", mysql_error(connection));
                }

	result=mysql_store_result(connection);	//variable to store results and display
	/*unsigned int */ col=mysql_num_fields(result);
    if(result!=NULL){
while(row = mysql_fetch_row(result))	//iterates from 1st to last row
{
	for(i=0;i<col;i++)
	{
	sprintf(buffer+32*i,"%-32s",row[i]);
	}
send_to(client_socket,buffer);
}
bzero(buffer,BLEN);
strcpy(buffer,"cmd_end");
send_to(client_socket,buffer);
}
else
    send_to(client_socket,"no result");
	mysql_free_result(result);

	goto half;

case 12://view available doctors
bzero(buffer,BLEN);
	strcpy(query,"SELECT d_name,date,time,location,service,network,id FROM t2");//WHERE p_username=\'");
	//strncat(query,username,strlen(username));
	//strcat(query,"\'");
		if (mysql_query(connection, query)) 	//function to request data from db
                {sprintf(buffer,"MYSQL ERROR: %s\n", mysql_error(connection));
                    printf("MYSQL ERROR: %s\n", mysql_error(connection));
                }

	result=mysql_store_result(connection);	//variable to store results and display
	/*unsigned int */ col=mysql_num_fields(result);

    while(row = mysql_fetch_row(result))	//iterates from 1st to last row
    {
	       for(i=0;i<col;i++)
	       {
	              sprintf(buffer+32*i,"%-32s",row[i]);
	       }
            send_to(client_socket,buffer);
    }
    bzero(buffer,BLEN);
    strcpy(buffer,"cmd_end");
    send_to(client_socket,buffer);
	mysql_free_result(result);
    bzero(buffer,BLEN);
    recv_from(client_socket, buffer);
    int id=atoi(buffer);

    bzero(query,BLEN);
    sprintf(query,"UPDATE t2 SET p_username=\'%s\' WHERE id=%d",username,id);

    if (mysql_query(connection, query)) 	//UPDATE t2 with patient username to create a relation between t1 and t2
    {
        sprintf(buffer,"MYSQL ERROR: %s\n", mysql_error(connection));
        printf("1 MYSQL ERROR: %s\n", mysql_error(connection));
    }
    else
    {
        bzero(query,BLEN);
    sprintf(query,"INSERT INTO t3 SELECT t2.id,t1.p_username,t2.d_username,t1.first_name,t2.d_name,t2.date,t2.time,t2.location,t2.service,t2.location FROM t1 INNER JOIN t2 ON t1.p_username=t2.p_username WHERE t2.id=%d",id);
        if (mysql_query(connection, query)) 	// UPDATE appointments(t3) table with booked appointment
            {
                sprintf(buffer,"MYSQL ERROR: %s\n", mysql_error(connection));
                printf("2 MYSQL ERROR: %s\n", mysql_error(connection));
            }
        else
            {
                bzero(query,BLEN);
                sprintf(query,"DELETE FROM t2 WHERE id=%d",id);
                if (mysql_query(connection, query)) 	// DELETE that entry from available appointments
                    {
                        sprintf(buffer,"MYSQL ERROR: %s\n", mysql_error(connection));
                        printf("MYSQL ERROR: %s\n", mysql_error(connection));
                    }
                else
                    strcpy(buffer,"appointment booked");
            }
        }
        send_to(client_socket,buffer);
	goto half;

    default: goto end;
}//switch end

}//while logged=1

while(logged==2)
{
    d_half:	bzero(buffer,BLEN);
   	    recv_from(client_socket, buffer);

	       int user_option=atoi(buffer);
           switch(user_option)
           {
               case 23:    printf("logging out\n");
	                       logged=0;
	                       goto main;
	                    break;
                case 20: bzero(buffer,BLEN);
	strcpy(query,"SELECT d_name,d_mobile,d_address,specality FROM t4 WHERE d_username=\'");
	strncat(query,username,strlen(username));
	strcat(query,"\'");
		if (mysql_query(connection, query)) 	//function to request data from db
                {sprintf(buffer,"MYSQL ERROR: %s\n", mysql_error(connection));
                    printf("MYSQL ERROR: %s\n", mysql_error(connection));
                }

	result=mysql_store_result(connection);	//variable to store results and display
	unsigned int  col=mysql_num_fields(result);

while(row = mysql_fetch_row(result))	//iterates from 1st to last row
{
	for(i=0;i<col;i++)
	{
	sprintf(buffer+32*i,"%-32s",row[i]);
	}
}
	mysql_free_result(result);
	send_to(client_socket,buffer);
	goto d_half;

case 22: bzero(buffer,BLEN);
	strcpy(query,"SELECT p_name,d_name,date,time,location,service,comments FROM t3 WHERE d_username=\'");
	strncat(query,username,strlen(username));
	strcat(query,"\'");
		if (mysql_query(connection, query)) 	//function to request data from db
                {sprintf(buffer,"MYSQL ERROR: %s\n", mysql_error(connection));
                    printf("MYSQL ERROR: %s\n", mysql_error(connection));
                }
	result=mysql_store_result(connection);	//variable to store results and display
	/*unsigned int */ col=mysql_num_fields(result);
while(row = mysql_fetch_row(result))	//iterates from 1st to last row
{
	for(i=0;i<col;i++)
	{
	sprintf(buffer+32*i,"%-32s",row[i]);
	}
send_to(client_socket,buffer);
}
bzero(buffer,BLEN);
strcpy(buffer,"cmd_end");
send_to(client_socket,buffer);
	mysql_free_result(result);

	goto d_half;

case 21:
bzero(buffer,BLEN);
recv_from(client_socket, buffer);
char *date;
date=(char * )malloc(sizeof(char)*strlen(buffer));
strncpy(date,buffer,strlen(buffer)+1);

char *time;
bzero(buffer,BLEN);
recv_from(client_socket, buffer);
time=(char * )malloc(sizeof(char)*strlen(buffer));
strncpy(time,buffer,strlen(buffer)+1);

bzero(query,BLEN);
sprintf(query," INSERT INTO t2 (d_username,date,time) VALUES ('%s','%s','%s')",username,date,time);

if (mysql_query(connection, query)) 	//function to request data from db
            {
                printf("MYSQL ERROR: %s\n", mysql_error(connection));
            }


result=mysql_store_result(connection);	//variable to store results and display
bzero(buffer,BLEN);
if(result!=NULL)
    strcpy(buffer,"not updated");
else
        strcpy(buffer,"inserted successful");
    mysql_free_result(result);

bzero(query,BLEN);
sprintf(query," UPDATE t2 INNER JOIN t4 ON t2.d_username=t4.d_username SET t2.d_name=t4.d_name,t2.location=t4.d_address,t2.service=t4.specality,t2.network=t4.network1 WHERE t2.d_username='%s'",username);

if (mysql_query(connection, query)) 	//function to request data from db
            {
                printf("MYSQL ERROR: %s\n", mysql_error(connection));
            }


	result=mysql_store_result(connection);	//variable to store results and display
    mysql_free_result(result);

    send_to(client_socket,buffer);
	goto d_half;

    default: printf(" wrong option\n");
		goto end;
}//switch end
}//while logged=2

end:    printf("connection closed\n");
	close(client_socket);
	mysql_close(connection);

            //close the socket connection, removes socket descriptor from table.
            pthread_exit(0);
}
