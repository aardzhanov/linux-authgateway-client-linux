#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <termios.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include "authclient.h"

//Global variables
int sockfd;
int debug;




//////////////////////////////////////////////////////////////////////////////////////
//Function, which read and parse config
//////////////////////////////////////////////////////////////////////////////////////
int readconfig(char * cfile, char * server, char * port, int * crypt, int * dbg, char * duser, int * daemonize)
{

 FILE * fp;
 char param[10];
 char value[50];

 fp = fopen(cfile, "r");
 if (!fp)
    {
     printf("%s\n", "Can not open config file.");
     return 1;
    }


 while(!feof(fp))
      {
       //Reading and parsing lines
       memset(&value[0], '\0', 50);
       memset(&param[0], '\0', 10);
       fscanf(fp, "%[^=]=%s\n", param, value);
       if (!strcmp(param, "host"))
       {
         strncpy(server, value, 50);
       }
       else if (!strcmp(param, "port"))
       {
         strncpy(port, value, 10);
       }
       else if (!strcmp(param, "crypt"))
       {
         if (!strcmp(value, "true"))
         {
           *crypt=1;
         }
         else
         {
           *crypt=0;
         }
       }
       else if (!strcmp(param, "debug"))
       {
         if (!strcmp(value, "true"))
         {
           *dbg=1;
         }
         else
         {
           *dbg=0;
         }
       }
       else if (!strcmp(param, "daemonize"))
       {
         if (!strcmp(value, "true"))
         {
           *daemonize=1;
         }
         else
         {
           *daemonize=0;
         }
       }
       else if (!strcmp(param, "defuser"))
       {
         strncpy(duser, value, 50);
       }
       //End reading and parsing lines
      }

 fclose(fp);

 return 0;

}
//////////////////////////////////////////////////////////////////////////////////////




//////////////////////////////////////////////////////////////////////////////////////
// Function which sends ALIVE messages
//////////////////////////////////////////////////////////////////////////////////////
void timer_handler (int signum)
{
 send(sockfd, "ALIVE", 5, 0);
 if(debug==1)
 {
   time_t now;
   now=time(NULL);
   printf("SENDDUMP ALIVE: %s", ctime(&now));
 }
}
//////////////////////////////////////////////////////////////////////////////////////



//////////////////////////////////////////////////////////////////////////////////////
// Daemonize function
//////////////////////////////////////////////////////////////////////////////////////
void daemonize(void)
{

  pid_t pid, sid;

  // Fork off the parent process
  pid = fork();
  
  if (pid < 0) 
     {
      exit(EXIT_FAILURE);
     }

  // If we got a good PID, then we can exit the parent process.
  if (pid > 0) 
     {
      exit(EXIT_SUCCESS);
     }

  // Change the file mode mask
  umask(0);

  sid = setsid();
  if (sid < 0) 
     {
      exit(EXIT_FAILURE);
     }
     if ((chdir(DAEMON_PATH)) < 0) 
        {
         exit(EXIT_FAILURE);
        }

  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);

}

//////////////////////////////////////////////////////////////////////////////////////



//////////////////////////////////////////////////////////////////////////////////////
// Main function
//////////////////////////////////////////////////////////////////////////////////////
int main(int argc, char *argv[])
{

 char authserver[50];
 char authport[10];
 int authcrypt;
 int daemon;
 int interval;
 char username[100]="\0";
 char password[100];
 int numbytes;
 char buf[256];
 struct hostent *he;
 struct sockaddr_in their_addr; // connector's address information
 struct itimerval timer;


 // Read config file
 if (readconfig(argc > 1 ? argv[1] : "~/.authclient.conf", &authserver[0], &authport[0], &authcrypt, &debug, &username[0], &daemon) !=0)
 {
	 exit(1);
 }


 //If debug=true dump all variables from config
 if (debug==1)
 {
	 printf("CONFDUMP Server: %s\nCONFDUMP Port: %s\nCONFDUMP Crypt: %i\nCONFDUMP Debug: %i\nCONFDUMP Daemonize: %i\nCONFDUMP Username: %s\n", authserver, authport, authcrypt, debug, daemon, username);
 }

 //Try to resolve hostname if need
 if ((he=gethostbyname(authserver)) == NULL)
 {
	printf("ERR : Can not resolve hostname\n");
	exit(1);
 }


 //Try to create socket
 if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
 {
	 printf("ERR : Can not create socket\n");
	 exit(1);
 }

 //Fill peer structure
 their_addr.sin_family = AF_INET;    // host byte order
 their_addr.sin_port = htons(atoi(authport));  // short, network byte order
 their_addr.sin_addr = *((struct in_addr *)he->h_addr);
 memset(&(their_addr.sin_zero), '\0', 8);  // zero the rest of the struct

 //Read username and password from console
 if (strlen(username)<=0)
 {
   printf("Username: ");
   fgets(&username[0], 99, stdin);
 }
 //chop newline character
 if (strlen(username)>0 && username[strlen(username)-1]=='\n')
 {
	 username[strlen(username)-1]='\0';
 }
 
 
 printf("Password: ");
 //Disable char echo and getting password
 static struct termios stored_settings;
 struct termios new_settings;
 tcgetattr(0,&stored_settings);
 new_settings = stored_settings;
 new_settings.c_lflag &= (~ECHO);
 tcsetattr(0,TCSANOW,&new_settings);
 fgets(&password[0], 99, stdin);
 tcsetattr(0,TCSANOW,&stored_settings);
 //chop newline character 
 if (strlen(password)>0 && password[strlen(password)-1]=='\n')
 {
	 password[strlen(password)-1]='\0';
 }
 
 
 if (debug==1)
 {
   printf("\nVARIDUMP Username: %s\nVARIDUMP Password: %s\n", username, password);
 }

 //try to connect
 if (connect(sockfd, (struct sockaddr *)&their_addr, sizeof(struct sockaddr)) == -1)
 {
	 printf("Can not connect to auth gateway. Please check your config.\n");
	 exit(1);
 }

 //Try to receive information from server
 if ((numbytes=recv(sockfd, buf, 255, 0)) == -1)
 {
   printf("Can not receive server settings\n");
   exit(1);
 }

 buf[numbytes] = '\0';

 //If debug is on, print received information
 if (debug==1)
 {
   printf("RECVDUMP %s\n",buf);
 }
 
 interval=atoi(buf);
 
 if (debug==1)
 {
   printf("VARIDUMP Timer interval: %i\n",interval);
 }
 

 //Send username and password

 memset(&buf[0], '\0', sizeof(buf));
 snprintf(&buf[0], sizeof(buf)-1, "%s@%s", username, password); 

 
 if(debug==1)
 {
   printf("SENDDUMP %s\n", buf);
 }
 send(sockfd, buf, strlen(buf), 0);
 
 memset(&buf[0], '\0', sizeof(buf));
 if ((numbytes=recv(sockfd, buf, 255, 0)) == -1)
 {
   perror("recv");
   exit(1);
 }

 buf[numbytes] = '\0';
  if(debug==1)
 {
 printf("RECVDUMP %s\n",buf);
 }
 
 if (daemon==1) 
{
	 daemonize();
 } 


 signal( SIGALRM, timer_handler);
  timer.it_value.tv_sec =  interval;
  timer.it_value.tv_usec = 0;
  timer.it_interval.tv_sec =  interval;
  timer.it_interval.tv_usec = 0;
  setitimer (ITIMER_REAL, &timer, NULL);


 

 
  while (1)
   {
	
	memset(&buf[0], '\0', sizeof(buf));
	if ((numbytes=recv(sockfd, buf, sizeof(buf), 0)) <=0)
		{
		perror("recv");
		close(sockfd);
		exit(1);
		}
	else
		{
		 if(debug==1)
		  {
		       printf("RECVDUMP %s\n",buf);
		  }
		}
     
   }




close(sockfd);
return 0;
}
//////////////////////////////////////////////////////////////////////////////////////
