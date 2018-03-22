all: meltdown.c
	gcc meltdown.c -O2 -fPIC -o meltdown