LIB = libxor-bio.a
SRCS = bio-xor.c
OBJS = $(SRCS:%.c=%.o)

CPPFLAGS = \
	-I.

CFLAGS = \
	-g -O2 -std=c99 -Wall -Wextra -pedantic -D_GNU_SOURCE \
	`pkg-config --cflags openssl`

LDFLAGS = \
	`pkg-config --libs openssl`

all: $(LIB) xor

%.o: %.c
	$(V_CC)$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(LIB): $(OBJS)
	$(V_AR)$(AR) rcs $@ $(OBJS)

xor: xor.o $(LIB)
	$(V_LINK)$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ xor.c $(LDFLAGS) $(LIB)

clean:
	rm -f $(LIB) $(OBJS) xor.o xor

.PHONY: all clean

# Quiet by default
VERBOSE ?= 0

# Define CC verbose macro
V_CC = $(v_CC_$(V))
v_CC_ = $(v_CC_$(VERBOSE))
v_CC_0 = @echo "  CC    " $(@F);

# Define AR verbose macro
V_AR = $(v_AR_$(V))
v_AR_ = $(v_AR_$(VERBOSE))
v_AR_0 = @echo "  AR    " $(@F);

# Define LINK verbose macro
V_LINK = $(v_LINK_$(V))
v_LINK_ = $(v_LINK_$(VERBOSE))
v_LINK_0 = @echo "  LINK  " $(@F);
