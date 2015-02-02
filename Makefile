MAKE = make

SUBDIRS = efi linux

all clean install :
	@for x in $(SUBDIRS) ; do \
		$(MAKE) -C $$x $@ ; \
	done
