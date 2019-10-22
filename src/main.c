int main(int argc, char const *argv[])
{
	if(argc < 2 || argc > 4)
		{
			printf("Nombre d'arguments invalide.\n");
			return -1;
		}

	// Récupération des arguments
	int mvalue;
	char *format;
	int oflag;
	int c;
	while((c = getopt(argc, argv, "mo:")) != -1)
	{
		switch(c)
		{
			case 'm':
				mvalue = optarg;
				break;
			case 'o':
				format = optarg;
				break;
			case '?':
				printf("Mauvais argument(s)\n");
				break;
		}
	}
	size_t size = strlen(argv[optind]);
	// Adresse IPV6 source
    char *hostname = malloc(size);
    memcpy(hostname, argv[optind], size);
		
	size = strlen(argv[optind + 1]);
	// Port UDP source
    int port = malloc(size);
    memcpy(port, argv[optind + 1], size);

    // Résout le problème de l'adresse
    struct sockaddr_in6 addr;
	const char *err = real_address(hostname, &addr);
	if (err) {
		fprintf(stderr, "Erreur dans la traduction de l'adresse %s: %s\n", host, err);
		return EXIT_FAILURE;
	}

	// Crée le socket
	int sfd = create_socket(&addr, port, NULL, -1);
	if(sfd < 0)
	{
		printf("Erreur lors de la création du socket\n");
		return -1;
	}
	
	// Connecte le client au serveur afin d'utiliser read_write_loop
	int wfc = wait_for_client(sfd);
	if(wfc < 0)
	{
		printf("Erreur lors de la connection au serveur\n");
		return -1;
	}

	int err = read_write_loop(sfd);
	if(err < 0)
	{
		return -1;
	}
	return 0;
}

/* Creates a socket and initialize it
 * @source_addr: if !NULL, the source address that should be bound to this socket
 * @src_port: if >0, the port on which the socket is listening
 * @dest_addr: if !NULL, the destination address to which the socket should send data
 * @dst_port: if >0, the destination port to which the socket should be connected
 * @return: a file descriptor number representing the socket,
 *         or -1 in case of error (explanation will be printed on stderr)
 */
int create_socket(struct sockaddr_in6 *source_addr,
                 int src_port,
                 struct sockaddr_in6 *dest_addr,
                 int dst_port)
{
	int err;
	int sfd = socket(AF_INET6, SOCK_DGRAM, 0);
	if(sfd < 0){
		return -1;
	}
	if(source_addr != NULL && src_port > 0){
		source_addr->sin6_port = htons(src_port);
		err = bind(sfd, (struct sockaddr*) source_addr, sizeof(struct sockaddr_in6));
		if (err != 0){
			return -1;
		}
	}
	if(dest_addr != NULL && dst_port > 0){
		dest_addr->sin6_port = htons(dst_port);
		err = connect(sfd, (struct sockaddr*) dest_addr, sizeof(struct sockaddr_in6));
		if (err != 0){
			return -1;
		}
	}
	return sfd;
}

/* Resolve the resource name to an usable IPv6 address
 * @address: The name to resolve
 * @rval: Where the resulting IPv6 address descriptor should be stored
 * @return: NULL if it succeeded, or a pointer towards
 *          a string describing the error if any.
 *          (const char* means the caller cannot modify or free the return value,
 *           so do not use malloc!)
 */
const char * real_address(const char *address, struct sockaddr_in6 *rval)
{
	int err;
	struct addrinfo hints;
	struct addrinfo *result;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET6;
    hints.ai_protocol = IPPROTO_UDP;

	err = getaddrinfo(address, NULL, &hints, &result);
    if(err != 0){
        return "Erreur : fonction getaddrinfo";
    }
	*rval = *((struct sockaddr_in6 *)(result->ai_addr));
	freeaddrinfo(result);
	return NULL;
}


/* Block the caller until a message is received on sfd,
 * and connect the socket to the source addresse of the received message
 * @sfd: a file descriptor to a bound socket but not yet connected
 * @return: 0 in case of success, -1 otherwise
 * @POST: This call is idempotent, it does not 'consume' the data of the message,
 * and could be repeated several times blocking only at the first call.
 */
int wait_for_client(int sfd){
	int err;
	char b[1024];
	struct sockaddr_in6 s;
	socklen_t len = sizeof(struct sockaddr_in6);

	err = recvfrom(sfd, &b, sizeof(b), MSG_PEEK, (struct sockaddr *) &s, &len);
	if (err < 0){
		return -1;
	}
	err = connect(sfd, (struct sockaddr *) &s, len);
	if (err < 0){
		return -1;
	}
	return 0;
}

/* Loop reading a socket and printing to stdout,
 * while reading stdin and writing to the socket
 * @sfd: The socket file descriptor. It is both bound and connected.
 * @return: as soon as stdin signals EOF
 */
void read_write_loop(const int sfd){

	fd_set rsfd;
	struct timeval tv;
	int err, retval;

	char* sb = (char *)malloc(1024);
	char* rb = (char *)malloc(1024);

	tv.tv_sec = 5;
	tv.tv_usec = 0;

	do{
		memset((void *)sb, 0, 1024);
		memset((void *)rb, 0, 1024);

		FD_ZERO(&rsfd);
		FD_SET(0 , &rsfd);
		FD_SET(sfd, &rsfd);

		err = select(sfd+1, &rsfd, NULL, NULL, &tv);
		if (err < 0){
			free(sb);
			free(rb);
			return;
		}

		retval = FD_ISSET(0, &rsfd);
		if(retval){
			retval = read(0, sb, 1024);
			if (retval < 0){
				free(sb);
				free(rb);
				return;
			}
			if (retval > 0){
				err = write(sfd, sb, retval);
				if (err < 0){
					free(sb);
					free(rb);
					return;
				}
			}
		}

		retval = FD_ISSET(sfd, &rsfd);
		if(retval){
			retval = read(sfd, rb, 1024);
			if(retval < 0){
				free(sb);
				free(rb);
				return;
			}
			if(err > 0){
				err = write(1, rb, retval);
				if (err < 0){
					free(sb);
					free(rb);
					return;
				}
			}
    }
	}while(feof(stdin)==0);
	free(sb);
	free(rb);
	return;
}