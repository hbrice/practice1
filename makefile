all:

	gcc -o uoenc uoenc.c -lgcrypt
	gcc -o uodec uodec.c -lgcrypt

clean:
	find . -type f -not -name 'uoenc.c' -not -name 'uodec.c' -not -name 'makefile' -not -name 'uoenc.h' -not -name 'uodec.h' | xargs rm