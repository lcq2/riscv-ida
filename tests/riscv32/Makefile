AS=riscv32-unknown-elf-as
CC=riscv32-unknown-elf-gcc
OBJCOPY=riscv32-unknown-elf-objcopy
OBJ=test_RV32I.o test_RV32M.o test_RV32A.o test_RV32F_RV32D.o
BIN=test_RV32A.bin test_RV32M.bin test_RV32F_RV32D.bin
ELF=test_RV32I.elf

%.o: %.s
	$(AS) -o $@ $<

%.bin: %.o
	$(OBJCOPY) -O binary $< $@

%.elf: %.o
	$(CC) -nostdlib -o $@ $<
	chmod -x $@

test: $(BIN) $(ELF)

.PHONY: clean

clean:
	rm -f *.bin *.o *.elf
