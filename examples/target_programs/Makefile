all: crash_test_argv crash_test_filename

CC = gcc

crash_test_filename: crash_test_filename.c
	$(CC) crash_test_filename.c -o bin/crash_test_filename

crash_test_argv: crash_test_filename.c
	$(CC) crash_test_argv.c -o bin/crash_test_argv
