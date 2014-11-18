MAKE = make

SUBDIRS = efi

all clean install :
	@for x in $(SUBDIRS) ; do \
		$(MAKE) -C $$x $@ ; \
	done
