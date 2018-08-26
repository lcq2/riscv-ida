SUBDIRS = riscv32 #\
	riscv64

all: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@

.PHONY: all $(SUBDIRS)

clean:
	$(MAKE) -C $(SUBDIRS) clean
