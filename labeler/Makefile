#
# Makefile
# Peter Jones, 2017-06-01 15:29
default : all

TOPDIR	?= $(shell pwd)/..
include $(TOPDIR)/Make.version
include $(TOPDIR)/Make.defaults

all:
	./make-images "Read firmware from device into a file"

clean:
	@rm -vf *.bmp *.png

install:

test:

.PHONY: all clean test install default

# vim:ft=make
#
