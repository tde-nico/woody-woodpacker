#include "woody-woodpacker.h"

Elf64_Phdr	*next_segment(t_packer *pack, Elf64_Ehdr *e_hdr, size_t count)
{
	Elf64_Phdr	*segment;

	segment = (Elf64_Phdr *)((char *)pack->map + (e_hdr->e_phoff + sizeof(Elf64_Phdr) * count));
	if (!segment || ((void *)segment >= (void *)pack->map + pack->size))
	{
		raise("Malformed file (section)");
		return (NULL);
	}
	return (segment);
}

Elf64_Shdr	*next_section(t_packer *pack, Elf64_Ehdr *e_hdr, size_t count)
{
	Elf64_Shdr	*section;

	section = (Elf64_Shdr *)((char *)pack->map + (e_hdr->e_shoff + sizeof(Elf64_Shdr) * count));
	if (!section || ((void *)section >= (void *)pack->map + pack->size))
	{
		raise("Malformed file (segment)");
		return (NULL);
	}
	return (section);
}
