AS=riscv32-unknown-elf-as
OBJCOPY=riscv32-unknown-elf-objcopy
OBJ=test_RV32F_RV32D.o
BIN=test_RV32F_RV32D.bin

%.o: %.s
	$(AS) -o $@ $<

%.bin: %.o
	$(OBJCOPY) -O binary $< $@

test: $(BIN)

.PHONY: clean

clean:
	rm -f *.bin *.o
