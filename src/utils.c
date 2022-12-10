#include "woody-woodpacker.h"

size_t	ft_strlen(char *str)
{
	size_t	len;

	len = 0;
	while (str[len] != '\0')
		++len;
	return (len);
}

int	raise(char *err)
{
	write(2, "[-] Error: ", 11);
	write(2, err, ft_strlen(err));
	write(2, "\n", 1);
	return (1);
}

void	*ft_memcpy(void *dst, const void *src, size_t n)
{
	char	*s1;
	char	*s2;
	size_t	count;

	s1 = (char*)dst;
	s2 = (char*)src;
	count = -1;
	while (++count < n)
		s1[count] = s2[count];
	return (s1);
}
