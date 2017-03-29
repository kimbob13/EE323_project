#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdbool.h>

#define BUF_SIZE (1024 * 500)

void *get_addr(struct sockaddr *sa)
{
	if(sa->sa_family == AF_INET)
		return &(((struct sockaddr_in *)sa)->sin_addr);
	else
		return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

int main(int argc, char *argv[])
{
	int sockfd, opt;
	char *port = NULL, *hostname = NULL;
	struct addrinfo hints, *res, *p;
	int rv;
	char s[INET6_ADDRSTRLEN], buf[BUF_SIZE] = {0}, prev_buf[BUF_SIZE] = {0};
	//ch = 0, prev_ch, i = 0;
	// bool terminate = false;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	while((opt = getopt(argc, argv, "h:p:")) != -1) {
		switch(opt) {
			case 'p':
				port = malloc(strlen(optarg) * sizeof(char));
				strcpy(port, optarg);
				break;
			case 'h':
				hostname = malloc(strlen(optarg) * sizeof(char));
				strcpy(hostname, optarg);
				break;
			default:
				fprintf(stderr, "usage: %s -p <port number> -h <hostname>\n", argv[0]);
				exit(EXIT_FAILURE);
		}
	}

	if(port == NULL) {
		fprintf(stderr, "Invalid port argumetn\n");
		exit(EXIT_FAILURE);
	}

	if((rv = getaddrinfo(hostname, port, &hints, &res)) != 0) {
		fprintf(stderr, "getaddrinfo - client: %s\n", gai_strerror(rv));
		return 1;
	}

	for(p = res; p != NULL; p = p->ai_next) {
		if((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}

		if(connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("client: connect");
			continue;
		}

		break;
	}

	if(p == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		return 2;
	}

	inet_ntop(p->ai_family, get_addr((struct sockaddr *)p->ai_addr), s, sizeof(s));
	printf("client: connected to %s\n", s);

	freeaddrinfo(res);

	while(1) {
		strcpy(prev_buf, buf);
		if(fgets(buf, BUF_SIZE - 1, stdin) == NULL ||
				(strcmp(buf, "\n") == 0 && strcmp(prev_buf, "\n") == 0)) {
			printf("Client %s terminated\n", s);
			exit(EXIT_SUCCESS);
		}
		else if(strcmp(buf, "\n") == 0)
			continue;
		if(write(sockfd, buf, BUF_SIZE) < 0)
			perror("send");
		bzero(buf, BUF_SIZE);
	}
}
