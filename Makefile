#
# Build, install, and run the demonstrator
#
#     $ make
#     $ make install
#     $ make run
#
# The user should setup an environment variable KEYSTONE_BUILD_DIR. The
# environment variable should refer to Keystone subdirectory 'build'.
#
KEYSTONE_BUILD_DIR ?= $(error Set KEYSTONE_BUILD_DIR enviromnment)
HAPP_TARGET = target/riscv64gc-unknown-linux-gnu/release
EAPP_TARGET = target/riscv64gc-unknown-none-elf/release

all:
	(cd schannel-lib; cargo build -v --release)
	(cd schannel-client; cargo build --target riscv64gc-unknown-linux-gnu -v --release)
	(cd schannel-host; cargo build -v --release)
	(cd schannel-eapp; cargo build -v --release)

install:
	@echo "Keystone build directory is $(KEYSTONE_BUILD_DIR)"
	cp $(HAPP_TARGET)/schannel-client $(KEYSTONE_BUILD_DIR)/overlay/root
	cp $(HAPP_TARGET)/schannel-host $(KEYSTONE_BUILD_DIR)/overlay/root
	cp $(EAPP_TARGET)/schannel-eapp $(KEYSTONE_BUILD_DIR)/overlay/root

run:
	@echo "Keystone build directory is $(KEYSTONE_DIR)"
	(cd $(KEYSTONE_BUILD_DIR); ./scripts/run-qemu.sh)

clean:
	(cd schannel-lib; cargo clean)
	(cd schannel-client; cargo clean)
	(cd schannel-host; cargo clean)
	(cd schannel-eapp; cargo clean)
