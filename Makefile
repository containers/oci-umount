src = $(wildcard *.c)
obj = $(src:.c=.o)

LDFLAGS = -lyajl -lselinux

systemdhook: $(obj)
	$(CC) -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	rm -rf $(obj) systemdhook
