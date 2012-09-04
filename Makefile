CC=/usr/local/cross-tools/bin/i386-mingw32msvc-gcc

ifconfig.exe: ifconfig.c
	$(CC) -s -o $@ $<

clean:
	rm -f ifconfig.exe

