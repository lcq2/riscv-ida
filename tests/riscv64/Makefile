AS=riscv64-unknown-elf-as
OBJCOPY=riscv64-unknown-elf-objcopy
OBJ=
BIN=

%.o: %.s
	$(AS) -o $@ $<

%.bin: %.o
	$(OBJCOPY) -O binary $< $@

test: $(BIN)

.PHONY: clean

clean:
	rm -f *.bin *.o
