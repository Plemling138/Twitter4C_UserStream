/* session.c - SSL connection for api.twitter.com
 * (C)2013-14 Plemling138
 */

#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "twilib.h"
#include "session.h"

#include "parson.h"

#define SHOW_RESPONSE 1
#define TIMEOUT_TIME 3

int sock = 0;

void parseJSON(char *buf) {
    JSON_Value *root = json_parse_string(buf);
    if(root == NULL) {
        return;
    }
    
    JSON_Object *tweet = json_value_get_object(root);
    
    //とりあえずCreated_atのないJSONは無視
    if(json_object_dotget_string(tweet, "created_at") == NULL) return;

    //Event通知の時
    if(json_object_dotget_string(tweet, "event") != NULL) {
		printf("\x07");
        printf("**********\n");
        printf("Action: %s by @%s\n", json_object_dotget_string(tweet, "event"), json_object_dotget_string(tweet, "source.screen_name"));
        if(strcmp(json_object_dotget_string(tweet, "event"), "favorite") == 0)
            printf("Target tweet: %s\nfrom @%s\n", json_object_dotget_string(tweet, "target_object.text"), json_object_dotget_string(tweet, "target.screen_name"));
        printf("**********\n\n");
        return;
    }
    
    printf("*** %s(@%s) ***\n", json_object_dotget_string(tweet, "user.name"), json_object_dotget_string(tweet, "user.screen_name"));
    printf("%s\n", json_object_dotget_string(tweet, "text"));
    printf("(%s)\n\n", json_object_dotget_string(tweet, "created_at"));
    
    json_value_free(root);
}

int SSL_send_and_recv(char *hostname, char *send_buf, char *recv_buf)
{
  SSL* ssl;
  SSL_CTX* ctx;
  int ret = 0, read_size = 0;

  struct sockaddr_in addr;
  struct hostent *host = 0;

  //DNS Resolve
  if((host = gethostbyname(hostname)) == NULL) {
    printf("Failed to resolve host\n");
    return -1;
  }

  //Set port number
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = *((unsigned long *)host->h_addr_list[0]);
  addr.sin_port = htons(443);

  //Create socket
  sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  
  //Connect
  if(connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
    printf("Cannot connect to Twitter server.\n");
    return -1;
  }

  //Initialize SSL
  SSL_load_error_strings();
  SSL_library_init();
  
  //Set CTX
  ctx = SSL_CTX_new(SSLv3_client_method());
  if(ctx == NULL) {
    return -2;
  }

  //Set SSL Connection
  ssl = NULL;
  ssl = SSL_new(ctx);
  if(ssl == NULL) {
    return -3;
  }
  
  //Set Socket and SSL
  ret = SSL_set_fd(ssl, sock);
  if(ret == 0) {
    return -4;
  }

  //Connect SSL
  ret = SSL_connect(ssl);
  if(ret != 1) {
    return -5;
  }

  //Send Request
  if(SSL_write(ssl, (void *)send_buf, strlen((void *)send_buf)) == -1) {
    return -6;
  }

  //Get Response
  char *json_string = (char *)calloc(8000, sizeof(char));
  int total_len = 0;

  while((read_size = SSL_read(ssl, recv_buf, BUF_SIZE-1)) > 0) {
	recv_buf[read_size] = '\0';
	//If Normal API Call, continue
	if(strstr(hostname, HOSTNAME) != NULL) {
		continue;
	}
	
	if(read_size <= 10) continue;
	
    if((total_len + read_size) < 8000) {
        strcat(json_string, recv_buf);
        total_len += read_size;
    }
    else {
        printf("Buffer Overflowed, clear\n");
        
        memset(json_string, '\0', 8000);
        total_len = 0;
        continue;
    }
    
    if(strstr(recv_buf, "\r\n") != NULL) {
        parseJSON(json_string);
        
        memset(json_string, '\0', 8000);
        total_len = 0;
    }
    
  }

  //Close SSL Session
  ret = SSL_shutdown(ssl);
  if(ret != 0) {
    return -7;
  }
  close(sock);
  free(json_string);
  
  return 0;
}
