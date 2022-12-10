#include "woody-woodpacker.h"

uint8_t payload[] =
{
	0x50, 0x57, 0x56, 0x52, 0x41, 0x50, 0xe8, 0x0c, 0x00, 0x00,
	0x00, 0x2e, 0x2e, 0x2e, 0x57, 0x4f, 0x4f, 0x44, 0x59, 0x2e,
	0x2e, 0x2e, 0x0a, 0xbf, 0x01, 0x00, 0x00, 0x00, 0x5e, 0xba,
	0x0c, 0x00, 0x00, 0x00, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x0f,
	0x05, 0x4d, 0x31, 0xc0, 0x48, 0x31, 0xc0, 0xb8, 0x42, 0x00,
	0x00, 0x00, 0x4c, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00, 0x83,
	0xf8, 0x00, 0x74, 0x13, 0x48, 0x31, 0xd2, 0x41, 0x8a, 0x10,
	0x80, 0xf2, 0x00, 0x41, 0x88, 0x10, 0xff, 0xc8, 0x49, 0xff,
	0xc0, 0xeb, 0xe8, 0x41, 0x58, 0x5a, 0x5e, 0x5f, 0x58, 0xe9,
	0xba, 0xba, 0xfe, 0xca,
};

unsigned int	get_payload_size()
{
	return (sizeof(payload));
}

void	set_key(uint8_t key)
{
	payload[72] = key;
}

uint8_t	*fake_page_inject(uint8_t *dst, t_bdata bdata)
{
	Elf64_Off	v1;
	Elf64_Off	v2;
	Elf64_Addr	v3;
	size_t		i;

	if (DEBUG)
		printf("\tsizeof code: %lu\n", bdata.payload_size);
	v1 =  bdata.s_size - (bdata.original_entrypoint - bdata.s_addr);
	if (DEBUG)
		printf("\t1 size insert:\t0x%lx\n", v1);
	ft_memcpy(&payload[48], &v1, sizeof(int));

	v2 = bdata.original_entrypoint - (bdata.p_vaddr + bdata.p_size) - 55 - 4;
	if (DEBUG)
		printf("\t2 addr insert:\t0x%lx\n", v2);
	ft_memcpy(&payload[55], &v2, sizeof(int));

 	v3 = (bdata.original_entrypoint - (bdata.p_vaddr + bdata.p_size)) - bdata.payload_size;
	if (DEBUG)
		printf("\toriginal_entrypoint insert:\t0x%lx\n", v3);
	ft_memcpy(&payload[bdata.payload_size - sizeof(int)], &v3, sizeof(int));

	i = -1;
	while (++i < bdata.payload_size)
		dst[i] = payload[i];
	return (dst);
}
