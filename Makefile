.PHONY: build
build: configure
	cmake --build build

.PHONY: configure
configure:
	cmake -B build -DCMAKE_C_FLAGS="-DLINUX -DLOG_LEVEL=DEBUG"

.PHONY: clean
clean:
	rm -rf build