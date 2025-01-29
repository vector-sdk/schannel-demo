RISCV_TARGET := riscv64gc-unknown-none-elf

all:
	cargo build --target $(RISCV_TARGET) --release

debug:
	cargo build -v --features debug_memory --target $(RISCV_TARGET) --release

clean:
	cargo clean
	rm -f *~ ./src/*~
