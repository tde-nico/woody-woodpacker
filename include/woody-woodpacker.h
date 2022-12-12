#ifndef WOODY_WOODPACKER_H
# define WOODY_WOODPACKER_H

# include <unistd.h>
# include <fcntl.h>
# include <stdlib.h>
# include <stdio.h>
# include <sys/stat.h>
# include <sys/mman.h>
# include <sys/types.h>
# include <elf.h>


# define ENABLED 0
# define DISABLED -1

# define PAGESIZE		4096
# define OUTPUT_NAME	"woody"

# define DEFAULT_KEY	0x42
# define KEY_SIZE		8
# define KEY_VALUES		"0123456789abcdef"

# define SET_SIGNATURE	ENABLED
# define SIGNATURE		0x424242

# define DEBUG			0

/*	USEFUL COMMANDS

readelf -h
xxd -l 64

*/

typedef struct		s_packer
{
	int				fd;
	off_t			size;
	char			*map;
	uint8_t			key[KEY_SIZE];
}					t_packer;

typedef struct		s_bdata
{
	uint64_t	p_size;
	Elf64_Addr	p_vaddr;
	Elf64_Off	p_offset;

	uint64_t	s_size;
	Elf64_Addr	s_addr;
	Elf64_Off	s_offset;

	Elf64_Addr	original_entrypoint;
	Elf64_Addr	payload_entrypoint;
	size_t		payload_size;

	unsigned int	p_vaddr2;
	unsigned int	end_of_text;
	unsigned int	old_entry;
}					t_bdata;

// code
unsigned int    get_payload_size();
void			set_key(uint8_t key);
uint8_t			*fake_page_inject(uint8_t *dst, t_bdata bdata);

// elf
Elf64_Shdr		*next_section(t_packer *pack, Elf64_Ehdr *e_hdr, size_t count);
Elf64_Phdr		*next_segment(t_packer *pack, Elf64_Ehdr *e_hdr, size_t count);

// infect
int				infect(t_packer *pack);

// utils
size_t			ft_strlen(char *src);
int				raise(char *err);
void			*ft_memcpy(void *dst, const void *src, size_t n);

#endif
