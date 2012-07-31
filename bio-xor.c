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
#include <string.h>

#define BIO_XOR_DEFAULT_KEY "s3cr3t"

typedef struct BIO_xor_ {
	const char *key;
	int keylen;
	int i;
} BIO_xor;

static int
xor_write(BIO *bio, const char *buffer, int length)
{
	int i;
	char xor_buffer[length];
	BIO_xor *self = bio->ptr;
	if (!buffer || 0 >= length) {
		return 0;
	}
	if (!self || !bio->next_bio) {
		return 0;
	}
	for (i = 0; i < length; ++i) {
		xor_buffer[i] = buffer[i] ^ self->key[self->i++ % self->keylen];
	}
	return BIO_write(bio->next_bio, xor_buffer, length);
}

static int
xor_read(BIO *bio, char *buffer, int length)
{
	int i, bytes;
	BIO_xor *self = bio->ptr;
	if (!buffer || 0 >= length) {
		return 0;
	}
	if (!self || !bio->next_bio) {
		return 0;
	}
	bytes = BIO_read(bio->next_bio, buffer, length);
	for (i = 0; i < bytes; ++i) {
		buffer[i] = buffer[i] ^ self->key[self->i++ % self->keylen];
	}
	return bytes;
}

static long
xor_ctrl(BIO *bio, int command, long arg1, void *arg2)
{
	BIO_xor *self = bio->ptr, *that;
	switch (command) {
	case BIO_CTRL_DUP:
		that = ((BIO *)arg2)->ptr;
		that->key = self->key;
		that->keylen = self->keylen;
		that->i = 0;
		return 1;
	case BIO_CTRL_RESET:
		self->i = 0;
		break;
	case BIO_C_SET_EX_ARG:
		if (arg2) {
			self->key = arg2;
			self->keylen = strlen(self->key);
		}
		break;
	default:
		break;
	}
	return BIO_ctrl(bio->next_bio, command, arg1, arg2);
}

static int
xor_new(BIO *bio)
{
	BIO_xor *self = (BIO_xor *)OPENSSL_malloc(sizeof(*self));
	if (!self) {
		return 0;
	}
	self->key = BIO_XOR_DEFAULT_KEY;
	self->keylen = sizeof(BIO_XOR_DEFAULT_KEY) - 1;
	self->i = 0;
	bio->init = 1;
	bio->ptr = self;
	bio->flags = 0;
	bio->num = 0;
	return 1;
}

static int
xor_free(BIO *bio)
{
	if (!bio) {
		return 0;
	}
	OPENSSL_free(bio->ptr);
	bio->ptr = NULL;
	bio->init = 0;
	bio->flags = 0;
	return 1;
}

static BIO_METHOD methods_xor = {
	BIO_TYPE_XOR, "XOR encryption",
	xor_write,
	xor_read,
	NULL, /* puts */
	NULL, /* gets */
	xor_ctrl,
	xor_new,
	xor_free,
	NULL /* callback_ctrl */
};

BIO_METHOD *
BIO_f_xor(void)
{
	return &methods_xor;
}
