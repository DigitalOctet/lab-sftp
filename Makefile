.PHONY: build
build: configure
	cmake --build build

# /* Level enum */
# #define DEBUG 0
# #define INFO 1
# #define NOTICE 2
# #define WARNING 3
# #define ERROR 4
# #define CRITICAL 5
# #define SILENT 6
.PHONY: configure
configure:
	cmake -B build -DCMAKE_C_FLAGS="-DLINUX -DLOG_LEVEL=DEBUG"

.PHONY: clean
clean:
	rm -rf build