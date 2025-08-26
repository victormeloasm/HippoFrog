
CXX ?= clang++
CXXFLAGS := -std=c++20 -O3 -fPIE -fvisibility=hidden -fstack-protector-strong -D_FORTIFY_SOURCE=2 -DNDEBUG -fstack-clash-protection -fcf-protection=full \
            -Wall -Wextra -Wconversion -Wshadow -Wformat=2 -Wno-unused-parameter -DOPENSSL_API_COMPAT=0x10100000L
LDFLAGS  := -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
LDLIBS   := -lssl -lcrypto

INCLUDES := -Iinclude
SRC := src/backend_openssl.cpp src/cmds.cpp src/main.cpp
OBJ := $(SRC:.cpp=.o)
BIN := bin/HippoFrog

all: $(BIN)

$(BIN): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) -pie $(LDLIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJ) $(BIN)

.PHONY: all clean
