# Makefile: build 32-bit or 64-bit assembly / executable
# 用法:
#   make foo.s        # 生成 foo.s（架构由 ARCH 控制）
#   make foo ARCH=32  # 生成 32 位可执行 foo32
#   make foo ARCH=64  # 生成 64 位可执行 foo64
#   make clean        # 清理

CC := gcc

# ---------- 架构 ----------
ARCH ?= 64

ifeq ($(ARCH),32)
    ARCHFLAG := -m32
    SUFFIX   := 32
else
    ARCHFLAG := -m64
    SUFFIX   := 64
endif

# ---------- 编译/链接选项 ----------
CFLAGS   := -O0 -g $(ARCHFLAG) -fno-omit-frame-pointer -fno-pie -fno-stack-protector
ASMFLAGS := $(CFLAGS) -S
LDFLAGS  := $(ARCHFLAG) -no-pie

SRCS := $(wildcard *.c)
ASMS := $(SRCS:.c=.s)
OBJS := $(SRCS:.c=.o)

.PHONY: all clean

# 默认目标：生成所有汇编文件
all: $(ASMS)

# ===== 规则 =====
# .c -> .s
%.s: %.c
	$(CC) $(ASMFLAGS) -o $@ $<

# .c -> .o
%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

# 链接成可执行文件，名字为 "源文件名 + 架构后缀"
%: %.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@$(SUFFIX) $<
	@echo "生成可执行文件: $@$(SUFFIX)"

# 清理
clean:
	rm -f $(ASMS) $(OBJS) *32 *64

