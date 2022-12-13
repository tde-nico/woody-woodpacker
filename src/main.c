#include "woody-woodpacker.h"

int	valid_magic(char *map)
{
	if (
		(*((unsigned char *)map + EI_MAG0) != ELFMAG0) ||
		(*((unsigned char *)map + EI_MAG1) != ELFMAG1) ||
		(*((unsigned char *)map + EI_MAG2) != ELFMAG2) ||
		(*((unsigned char *)map + EI_MAG3) != ELFMAG3)
	)
		return (raise("Target is not an elf file"));
	if (SET_SIGNATURE == ENABLED && *((uint32_t *)&map[EI_PAD]) == SIGNATURE)
		return (raise("Binary already infected"));
	return (0);
}

int	init(t_packer *pack, char **argv)
{
	struct stat	st;
	uint8_t		default_key = DEFAULT_KEY;

	pack->fd = open(argv[1], O_RDONLY);
	if (pack->fd < 0)
		return (raise("Error while opening the target"));
	if (fstat(pack->fd, &st) != 0)
	{
		close(pack->fd);
		return (raise("Error gatering file info"));
	}
	pack->map = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, pack->fd, 0);
	if (pack->map == MAP_FAILED)
	{
		close(pack->fd);
		return (raise("Error mapping the target"));
	}
	pack->size = st.st_size;
	if (argv[2] == NULL)
		ft_memcpy(pack->key, &default_key, KEY_SIZE);
	else
		ft_memcpy(pack->key, &argv[2][0], KEY_SIZE); // TODO (better encryption)
	set_key(*(pack->key));
	return (0);
}

int	build(t_packer *pack)
{
	if (valid_magic(pack->map))
		return (1);
	if (*((unsigned char *)pack->map + EI_CLASS) != ELFCLASS64)
		return (raise("Target not a 64bit file"));
	if (infect(pack))
		return (1);
	return (0);
}

int	clean(t_packer *pack)
{
	if (close(pack->fd) == -1)
		return (raise("Error closing file"));
	if (munmap(pack->map, pack->size) == -1)
		return (raise("Error unmapping memory"));
	return (0);
}

int	main(int argc, char **argv)
{
	t_packer	pack;

	if (argc < 2 || argc > 3)
		return (raise("Usage: ./woody_woodpacker target [key]"));
	if (
		init(&pack, argv) ||
		build(&pack)
	)
		return (1 + clean(&pack));
	printf("[+] Success building payload with key: 0x%x\n", *(pack.key));
	if (clean(&pack))
		return (1);
	return (0);
}
