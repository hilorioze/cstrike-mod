.PHONY: all clean

all:
	cmake -B build && cmake --build build -j

clean:
	rm -rf build
