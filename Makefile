CC=gcc
OBJ=nfc-scanner.o

nfc-scanner: $(OBJ)
	$(CC) -o $@ $^ `pkg-config --libs libfreefare` -lmosquitto

%.o: %.c
	$(CC) -c -o $@ $< `pkg-config --cflags libfreefare`

clean:
	rm -f *.o nfc-scanner
