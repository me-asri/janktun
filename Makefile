TARGET := janktun

SRCDIR := src
INCDIR := inc
BINDIR := bin
OBJDIR := obj

SRCEXT := c
DEPEXT := h
OBJEXT := o

CC ?= gcc

CFLAGS := -std=c11 -Wall -D_GNU_SOURCE
CFLAGS_REL := -DNDEBUG -Werror -O3 -flto
CFLAGS_DBG := -DDEBUG -Og -g

LDFLAGS :=

INC:= -iquote$(INCDIR)
LIB:=

ifeq ($(DEBUG),1)
	CFLAGS += $(CFLAGS_DBG)
else
	CFLAGS += $(CFLAGS_REL)
endif

ifeq ($(NATIVE),1)
	CFLAGS += -march=native
endif

ifeq ($(PREFIX),)
	PREFIX := /usr/local
endif

SRCS := $(wildcard $(SRCDIR)/*.$(SRCEXT) $(SRCDIR)/**/*.$(SRCEXT))
DEPS := $(wildcard $(INCDIR)/*.$(DEPEXT) $(INCDIR)/**/*.$(DEPEXT))
OBJS := $(patsubst $(SRCDIR)/%, $(OBJDIR)/%, $(SRCS:.$(SRCEXT)=.$(OBJEXT)))

BIN := $(BINDIR)/$(TARGET)

.PHONY: all strip clean install uninstall

all: $(BIN)

strip:
	strip -s $(BIN)

$(BIN): $(OBJS)
	@mkdir -p $(BINDIR)

	$(CC) -o $(BIN) $^ $(CFLAGS) $(LDFLAGS) $(LIB)

	@echo Compiled $(TARGET)

$(OBJDIR)/%.$(OBJEXT): $(SRCDIR)/%.$(SRCEXT) $(DEPS)
	@mkdir -p $(dir $@)

	$(CC) -c -o $@ $< $(CFLAGS) $(INC)

clean:
	rm -rf $(OBJDIR) $(BINDIR)

install: $(BIN)
	install -d $(DESTDIR)$(PREFIX)/bin/
	install -m 755 $(BIN) $(DESTDIR)$(PREFIX)/bin/

uninstall:
	rm $(DESTDIR)$(PREFIX)/bin/$(TARGET)
