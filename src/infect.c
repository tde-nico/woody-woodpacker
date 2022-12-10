#include "woody-woodpacker.h"

int	create_binary(t_packer *infected, t_packer *pack)
{
	infected->fd = open(OUTPUT_NAME, O_RDWR | O_CREAT | O_TRUNC, 0777);
	if (infected->fd < 0)
		return (raise("Error opening packed"));
	infected->map = mmap(NULL, pack->size + PAGESIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_SHARED, infected->fd, 0);
	if (infected->map == MAP_FAILED)
	{
		close(infected->fd);
		return (raise("Error mapping payload"));
	}
	lseek(infected->fd, pack->size + PAGESIZE, SEEK_SET);
	write(infected->fd, "0x0", 1);
	close(infected->fd);
	return (0);
}

int	is_entry_segment(Elf64_Ehdr *e_hdr, Elf64_Phdr *p_hdr)
{
	if ((e_hdr->e_entry > p_hdr->p_vaddr) && e_hdr->e_entry < (p_hdr->p_vaddr + p_hdr->p_filesz))
		return (1);
	return (0);
}

int	modify_segment(t_packer *pack, Elf64_Ehdr *e_hdr, t_bdata *bdata)
{
	int			i;
	int			increment;
	Elf64_Phdr	*p_hdr;

	i = -1;
	increment = 0;
	while (++i < e_hdr->e_phnum)
	{
		p_hdr = next_segment(pack, e_hdr, i);
		if (p_hdr == NULL)
			return (raise("Error modifing segment"));
		if (increment)
			p_hdr->p_offset += PAGESIZE;
		if (is_entry_segment(e_hdr, p_hdr))
		{
			bdata->p_size = p_hdr->p_filesz;
			bdata->p_vaddr = p_hdr->p_vaddr;
			bdata->p_offset = p_hdr->p_offset;

			p_hdr->p_flags |= PF_W;
			bdata->original_entrypoint = e_hdr->e_entry;
			bdata->payload_entrypoint = p_hdr->p_vaddr + p_hdr->p_filesz;

			p_hdr->p_filesz += bdata->payload_size;
			p_hdr->p_memsz += bdata->payload_size;

			if (DEBUG)
			{
				printf("segment %d -> .text :\n", i);
				printf("\told_entry:\t0x%lx\n\tnew_entry:\t0x%lx\n", e_hdr->e_entry, bdata->payload_entrypoint);
				printf("\tp_size:\t\t0x%lx\n", bdata->p_size);
				printf("\tp_offset:\t0x%lx\n", bdata->p_offset);
				printf("\tp_vaddr:\t0x%lx\n\n", bdata->p_vaddr);
			}

			e_hdr->e_entry = bdata->payload_entrypoint;
			increment = 1;
		}
	}
	return (0);
}

int	is_entry_section(t_bdata *bdata, Elf64_Shdr *s_hdr)
{
	if ((bdata->original_entrypoint >= s_hdr->sh_addr)
		&& (bdata->original_entrypoint < s_hdr->sh_addr + s_hdr->sh_size))
		return (1);
	return (0);
}

int	modify_section(t_packer *pack, Elf64_Ehdr *e_hdr, t_bdata *bdata)
{
	int			i;
	int			increment;
	Elf64_Shdr	*s_hdr;

	i = -1;
	increment = 0;
	s_hdr = (Elf64_Shdr *)((char *)e_hdr + e_hdr->e_shoff);
	while (++i < e_hdr->e_shnum)
	{
		s_hdr = next_section(pack, e_hdr, i);
		if (s_hdr == NULL)
			return (raise("Error modifing segment"));
		if (increment)
			s_hdr->sh_offset += PAGESIZE;
		if (is_entry_section(bdata, s_hdr))
		{
			bdata->s_size = s_hdr->sh_size;
			bdata->s_addr = s_hdr->sh_addr;
			bdata->s_offset = s_hdr->sh_offset;

			if (DEBUG)
			{
				printf("section %d -> .text :\n", i);
				printf("\ts_size:\t\t0x%lx\n", bdata->s_size);
				printf("\ts_offset:\t0x%lx\n", bdata->s_offset);
				printf("\ts_addr:\t\t0x%lx\n\n", bdata->s_addr);
			}

			e_hdr->e_entry = bdata->payload_entrypoint;
			increment = 1;
		}
		if ((s_hdr->sh_offset + s_hdr->sh_size) == (bdata->p_offset + bdata->p_size))
		{
			if (DEBUG)
				printf("Last section found %d:\n", i);
			s_hdr->sh_size += bdata->payload_size;
			increment = 1;
		}
	}
	return (0);
}

void	insert_signature(t_packer *pack)
{
	if (SET_SIGNATURE == ENABLED)
	{
		if (DEBUG)
			printf("\t\tsignature set : %s\n", &pack->map[EI_PAD]);
		*(uint32_t *)&pack->map[EI_PAD] = SIGNATURE;
	}
}

void	insert_shellcode(t_packer *pack, t_packer infected, t_bdata bdata)
{
	uint8_t	fake_page[PAGESIZE] = {0};

	size_t	offset_src = 0;
	size_t	offset_dst = 0;
	int		i = 0;

	size_t	encrypt_begin = bdata.s_offset + (bdata.original_entrypoint - bdata.s_addr);
	size_t	encrypt_end = bdata.s_offset + bdata.s_size;
	size_t	payload_begin = bdata.p_offset + bdata.p_size;
	size_t	payload_end = payload_begin + PAGESIZE;
	size_t	eof = pack->size + PAGESIZE;

	if (DEBUG)
	{
		printf("Adresses:\n");
		printf("\tencrypt_begin:\t0x%lx -> %lu\n", encrypt_begin, encrypt_begin);
		printf("\tencrypt_end:\t0x%lx -> %lu\n", encrypt_end, encrypt_end);
		printf("\tpayload_begin:\t0x%lx -> %lu\n", payload_begin, payload_begin);
		printf("\tpayload_end:\t0x%lx -> %lu\n", payload_end, payload_end);
		printf("\teof:\t0x%lx -> %lu\n\n", eof, eof);
	}

	while (offset_dst < encrypt_begin)
		infected.map[offset_dst++] = pack->map[offset_src++];
	while (offset_dst < encrypt_end)
		infected.map[offset_dst++] = pack->map[offset_src++] ^ *(pack->key);
	while (offset_dst < payload_begin)
		infected.map[offset_dst++] = pack->map[offset_src++];
	fake_page_inject(fake_page, bdata);
	while (offset_dst < payload_end)
		infected.map[offset_dst++] = fake_page[i++];
	while (offset_dst < eof)
		infected.map[offset_dst++] = pack->map[offset_src++];
}

int	infect(t_packer *pack)
{
	t_bdata		bdata;
	t_packer	infected;
	Elf64_Ehdr	*e_hdr;

	e_hdr = (Elf64_Ehdr *)pack->map;
	bdata.payload_size = get_payload_size();
	if (!create_binary(&infected, pack))
	{
		if (!modify_segment(pack, e_hdr, &bdata))
		{
			if (!modify_section(pack, e_hdr, &bdata))
			{
				e_hdr->e_shoff += PAGESIZE;
				insert_signature(pack);
				insert_shellcode(pack, infected, bdata);
				return (0);
			}
		}
	}
	munmap(infected.map, pack->size + PAGESIZE);
	return (1);
}
