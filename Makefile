CC = gcc
CFLAGS = -O3 -std=c99 -Wall -Wextra -Werror -fPIC
all: build/libguardrail.so
build/libguardrail.so: src/scanner.c include/guardrail.h
	mkdir -p build
	$(CC) $(CFLAGS) -shared -Iinclude src/scanner.c -lm -o $@
test:
	python -m pytest -q
