TARGET_ARCH := riscv64gc-unknown-linux-gnu
x86_64: TARGET_ARCH := x86_64-unknown-linux-gnu


all: riscv64

riscv64:
	cargo build --target $(TARGET_ARCH) --release

x86_64:
	cargo build -v --target $(TARGET_ARCH) --release

debug:
	cargo build -v --features debug_memory --target $(TARGET_ARCH) --release

clean:
	cargo clean
	rm -f *~ ./src/*~
