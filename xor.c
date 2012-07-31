/*
 * Copyright 2012 Michael Steinert
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "bio-xor.h"
#include <ctype.h>
#include <getopt.h>
#include <openssl/bio.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static FILE *
help(FILE *stream, const char *name)
{
	fprintf(stream, "usage: %s [OPTIONS]...\n\n", name);
	fprintf(stream, " -h, --help\t\t\t"
			"Show this help\n");
	fprintf(stream, " -H, --hex\t\t\t"
			"Write output as hex escape codes [false]\n");
	fprintf(stream, " -i <FILE>, --input=<FILE>\t"
			"The input file [stdin]\n");
	fprintf(stream, " -k <SECRET>, --key=<SECRET>\t"
			"The XOR key [secret]\n");
	fprintf(stream, " -o <FILE>, --output=<FILE>\t"
			"The output file [stdout]\n");
	fprintf(stream, " -v, --version\t\t\t"
			"Show the version number\n\n");
	return stream;
}

static FILE *
version(FILE *stream)
{
	fprintf(stream, "%s/%s\n\n", "xor", "1.0");
	return stream;
}

int
main(int argc, char **argv)
{
	bool hex = false;
	FILE *output = NULL;
	BIO *input = NULL, *xor = NULL;
	char buffer[BUFSIZ], *real_key = NULL;
	int status = EXIT_SUCCESS, opt, i, j, bytes;
	const char *infile = NULL, *key = NULL, *outfile = NULL;
	const struct option options[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "hex", no_argument, NULL, 'H' },
		{ "input", required_argument, NULL, 'i' },
		{ "key", required_argument, NULL, 'k' },
		{ "output", required_argument, NULL, 'o' },
		{ "version", no_argument, NULL, 'v' },
		{ NULL, no_argument, NULL, '\0' }
	};
	const char *sopts = "hHi:k:o:v";
	while (-1 != (opt = getopt_long(argc, argv, sopts, options, &i))) {
		switch (opt) {
		case 'h': /* help */
			help(version(stdout), argv[0]);
			goto exit;
		case 'H': /* hex */
			hex = true;
			break;
		case 'i': /* input */
			infile = optarg;
			break;
		case 'k': /* key */
			key = optarg;
			break;
		case 'o': /* output */
			outfile = optarg;
			break;
		case 'v': /* version */
			version(stdout);
			goto exit;
		default:
			fprintf(stderr, "unrecognized option: `%s'\n",
					argv[optind - 1]);
			goto error;
		}
	}
	if (infile) {
		input = BIO_new_file(infile, "r");
	} else {
		input = BIO_new_fp(stdin, BIO_NOCLOSE);
	}
	if (!input) {
		goto error;
	}
	xor = BIO_new(BIO_f_xor());
	if (!xor) {
		goto error;
	}
	if (key) {
		size_t i;
		const char *p;
		char *q, hex[3];
		real_key = calloc(strlen(key) + 1, sizeof(char));
		if (!real_key) {
			goto error;
		}
		p = key;
		q = real_key;
		while (*p) {
			if ('\\' == *p) {
				++p;
				switch (*p) {
				case '\0':
					break;
				case 'b':
					*q++ = '\b';
					break;
				case 'f':
					*q++ = '\f';
					break;
				case 'n':
					*q++ = '\n';
					break;
				case 'r':
					*q++ = '\r';
					break;
				case 't':
					*q++ = '\t';
					break;
				case 'x':
					for (i = 0; i < 2; ++i) {
						++p;
						if (!*p || !isxdigit(*p)) {
							goto error;
						}
						hex[i] = *p;
					}
					hex[2] = '\0';
					*q++ = strtol(hex, NULL, 16);
					break;
				default:
					*q++ = *p;
					break;
				}
			} else {
				*q++ = *p;
			}
			++p;
		}
		BIO_ctrl(xor, BIO_C_SET_EX_ARG, 0L, (void *)real_key);
	}
	xor = BIO_push(xor, input);
	if (outfile) {
		output = fopen(outfile, "w");
	} else {
		output = stdout;
	}
	if (!output) {
		goto error;
	}
	while (true) {
		bytes = BIO_read(xor, buffer, sizeof(buffer));
		if (bytes > 0) {
			if (hex) {
				for (j = 0; j < bytes; ++j) {
					fprintf(output, "\\x%02x", buffer[j]);
				}
			} else {
				fwrite(buffer, bytes, 1, output);
			}
			if (bytes != sizeof(buffer)) {
				break;
			}
		} else if (0 == bytes) {
			break;
		} else {
			goto error;
		}
	}
	if (hex && (stdout == output)) {
		fputc('\n', stdout);
	}
exit:
	free(real_key);
	BIO_vfree(input);
	BIO_vfree(xor);
	if (output) {
		fclose(output);
	}
	return status;
error:
	status = EXIT_FAILURE;
	goto exit;
}
