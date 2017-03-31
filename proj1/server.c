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

#define BACKLOG 20
#define BUF_SIZE (1024 * 500)
#define UNUSED __attribute__ ((unused))

void sigchld_handler(int s UNUSED)
{
	while(waitpid(-1, NULL, WNOHANG) > 0);
}

void *get_addr(struct sockaddr *sa)
{
	if(sa->sa_family == AF_INET)
		return &(((struct sockaddr_in *)sa)->sin_addr);
	else
		return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

int main(int argc, char *argv[])
{
	int sockfd, new_fd, opt;
	char *port = NULL;	/* Input port number from command line argument */
	struct addrinfo hints, *res, *p;
	struct sockaddr_storage their_addr;
	socklen_t sin_size;
	struct sigaction sa;
	int yes = 1;
	char s[INET6_ADDRSTRLEN], buf[BUF_SIZE] = {0};
	int rv, child_pid;
	int numbytes;

	/* This socket can accept IPv4 and IPv6, types is TCP socket */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	while((opt = getopt(argc, argv, "p:")) != -1) {
		switch(opt) {
			case 'p':	/* There are only one argument, port number */
				port = malloc(strlen(optarg) * sizeof(char));
				strcpy(port, optarg);
				break;
			default:
				fprintf(stderr, "usage: %s -p <port number>\n", argv[0]);
				exit(EXIT_FAILURE);
		}
	}

	if(port == NULL) {
		fprintf(stderr, "Invalid port argument\n");
		exit(EXIT_FAILURE);
	}

	/* Get address information */
	if((rv = getaddrinfo(NULL, port, &hints, &res)) != 0) {
		fprintf(stderr, "getaddrinfo - server: %s\n", gai_strerror(rv));
		return 1;
	}
	
	/* Search for valid node in res list */
	for(p = res; p != NULL; p = p->ai_next) {
		/* Create socket given by getaddrinfo */
		if((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			perror("server: socket");
			continue;
		}

		if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
			perror("setsockopt");
			exit(EXIT_FAILURE);
		}

		/* Bind socket to specified port */
		if(bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("server: bind");
			continue;
		}

		break;

	}

	if(p == NULL) {
		fprintf(stderr, "server: failed to bind\n");
		return 2;
	}

	freeaddrinfo(res);

	/* Listen input for current socket */
	if(listen(sockfd, BACKLOG) == -1) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

	sa.sa_handler = sigchld_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if(sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("sigaction");
		exit(EXIT_FAILURE);
	}

	while(1) {
		sin_size = sizeof(their_addr);
		/* If there are connection request, accept that connection,
		   and create new file description for that connection */
		new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
		if(new_fd == -1) {
			perror("accept");
			continue;
		}

		inet_ntop(their_addr.ss_family, get_addr((struct sockaddr *)&their_addr), s, sizeof(s));
		/* Create child process for newly created connection */
		child_pid = fork();
		if(child_pid == 0) {
			/* Socket file description is not needed for child process */
			close(sockfd);
			while(1) {
				/* Read messages from client */
				numbytes = read(new_fd, buf, BUF_SIZE);
				if(numbytes == -1) {
					perror("read");
					break;
				}
				/* If client is terminated, break while loop */
				else if(numbytes == 0)
					break;
				/* Print received message to standard output */
				write(STDOUT_FILENO, buf, BUF_SIZE);
				/* Claer buffer for next message */
				bzero(buf, BUF_SIZE);
			}

			close(new_fd);
			exit(EXIT_SUCCESS);
		}
		close(new_fd);
	}

	return 0;
}
