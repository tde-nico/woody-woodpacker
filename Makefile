NAME			= woody_woodpacker

CC				= gcc
CFLAGS			= -Werror -Wall -Wextra
AS				= nasm
ASFLAGS			= -f elf64

RM				= rm -rf
MD				= mkdir -p

SRC_DIR			= src
INCLUDE			= include
OBJ_DIR			= obj
SRC_SUB_DIRS	= $(shell find $(SRC_DIR) -type d)
OBJ_SUB_DIRS	= $(SRC_SUB_DIRS:$(SRC_DIR)%=$(OBJ_DIR)%)
SRCS_C			= $(foreach DIR, $(SRC_SUB_DIRS), $(wildcard $(DIR)/*.c))
SRCS_S			= $(foreach DIR, $(SRC_SUB_DIRS), $(wildcard $(DIR)/*.s))
OBJS			= $(SRCS_C:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o) $(SRCS_S:$(SRC_DIR)/%.s=$(OBJ_DIR)/%.o)



all: $(NAME)

$(NAME): $(OBJ_SUB_DIRS) $(OBJS)
	$(CC) $(CFLAGS) -I $(INCLUDE) $(OBJS) -o $@

$(OBJ_DIR)/%.o : $(SRC_DIR)/%.s
	$(AS) $(ASFLAGS) -o $@ $<

$(OBJ_DIR)/%.o : $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -I $(INCLUDE) -c $< -o $@

$(OBJ_SUB_DIRS):
	$(MD) $(OBJ_SUB_DIRS)


clean:
	$(RM) $(OBJ_DIR)

fclean: clean
	$(RM) $(NAME)

re: fclean all


.PHONY: all clean fclean re
