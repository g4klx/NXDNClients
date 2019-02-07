SUBDIRS = NXDNGateway NXDNParrot NXDNReflector

CLEANDIRS = $(SUBDIRS:%=clean-%)



all: $(SUBDIRS)



$(SUBDIRS):

	$(MAKE) -C $@



clean: $(CLEANDIRS)



$(CLEANDIRS): 

	$(MAKE) -C $(@:clean-%=%) clean



.PHONY: $(SUBDIRS) $(CLEANDIRS)
