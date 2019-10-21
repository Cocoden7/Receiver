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
    char *hostname = malloc(size);
    memcpy(hostname, argv[optind], size);
		
	size = strlen(argv[optind + 1]);
    char *port = malloc(size);
    memcpy(port, argv[optind + 1], size);

	return 0;
}