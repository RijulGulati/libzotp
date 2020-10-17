ifeq ($(PREFIX),)
	PREFIX = /usr/local
endif

LIB_NAME = libzotp.so
VERSION = 0.0.1
LIB = $(LIB_NAME).$(VERSION)

OUT_DIR = obj
SRC_DIR = src
MKDIR = mkdir -p $(OUT_DIR)
OUT_LIB = $(OUT_DIR)/$(LIB)

CC = gcc
CFLAGS = -g -Wall
LIBS = -lssl -lcrypto -lm
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(addprefix $(OUT_DIR)/, $(notdir $(SRCS:.c=.o)))


.PHONY: all install uninstall clean directories

all: directories $(OUT_LIB)

$(OUT_LIB): $(OBJS)
	$(CC) $(CFLAGS) $(LIBS) -shared -o $@ $^

$(OUT_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) $(LIBS) -c $< -o $@

install:
	install $(OUT_LIB) $(PREFIX)/lib
	ln -sf $(PREFIX)/lib/$(LIB) $(PREFIX)/lib/$(LIB_NAME)
	install -d $(PREFIX)/include/zotp
	install -m 644 include/zotp/*.h $(PREFIX)/include/zotp

uninstall:
	rm -rf $(PREFIX)/lib/$(LIB) $(PREFIX)/lib/$(LIB_NAME) $(PREFIX)/include/zotp

clean:
	rm -rf $(OUT_DIR)/

directories:
	$(MKDIR)

