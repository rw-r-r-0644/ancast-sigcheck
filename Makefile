
LDFLAGS	:= -lssl -lcrypto
CFLAGS	:= -O2

SRCS	:= $(wildcard source/*.c)
OBJS	:= $(patsubst source/%.c,build/%.o,$(SRCS))

ancast_sigcheck: $(OBJS)
	$(info LINK $@)
	@gcc -o $@ $(LDFLAGS) $(OBJS)

build/%.o : source/%.c
	$(info CC $<)
	@mkdir -p $(dir $@)
	@gcc $(SRCFLAGS) -c -o $@ $<

clean:
	$(info CLEAN ...)
	@rm -rf build
	@rm -f ancast_sigcheck
