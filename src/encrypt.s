section .text

global _encrypt

; void	_encrypt(char *dst, char *src, size_t start, size_t end, uint8_t key);

_encrypt:
	; | rdi | rsi | rdx   | rcx | r8  |
	; | dst | src | start | end | key |
	add rdi, rdx
	mov r9, rdi
	add rcx, rsi
	dec rdx
	add rdx, rsi
	mov rsi, r8

loop:
	; | rdx       | rcx        | rsi | r9  |
	; | curr_addr | final_addr | key | dst |
	inc rdx
	mov rdi, [rdx]
	call _crypt
	mov [r9], rax

	inc r9
	cmp rdx, rcx
	jne loop
	ret

_crypt:
	; | rdi           | rsi |
	; | char_to_crypt | key |
	push rdi
	push rsi
	xor rdi, rsi
	mov rax, rdi
	pop rsi
	pop rdi
	ret
