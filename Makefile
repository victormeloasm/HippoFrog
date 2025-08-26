
# HippoFrog v2.2 - Makefile
CXX ?= g++
PKG_CONFIG ?= pkg-config

OPENSSL_CFLAGS := $(shell $(PKG_CONFIG) --cflags openssl 2>/dev/null)
OPENSSL_LDLIBS := $(shell $(PKG_CONFIG) --libs openssl 2>/dev/null)
ifeq ($(strip $(OPENSSL_LDLIBS)),)
  # Fallback if pkg-config is missing
  OPENSSL_LDLIBS := -lssl -lcrypto
endif

CXXFLAGS ?= -std=c++20 -O3 -march=native -mtune=native -flto -fPIC -fvisibility=hidden \
  -fno-plt -fno-rtti -fno-exceptions -fno-asynchronous-unwind-tables -pipe -DNDEBUG \
  -Wall -Wextra -Wconversion -Wshadow -Wformat=2 -Wno-unused-parameter \
  -DOPENSSL_API_COMPAT=0x10100000L -Wno-deprecated-declarations \
  $(OPENSSL_CFLAGS) -Iinclude

LDFLAGS ?= -flto -Wl,-O3 -Wl,--as-needed -Wl,--gc-sections
LDLIBS ?= $(OPENSSL_LDLIBS)

SRC := src/main.cpp src/backend_openssl.cpp src/cmds.cpp
OBJ := $(SRC:.cpp=.o)
BIN := bin/HippoFrog

all: $(BIN)

bin:
	mkdir -p bin

$(BIN): bin $(OBJ)
	$(CXX) $(OBJ) $(LDFLAGS) $(LDLIBS) -o $@

src/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) -Iinclude -c $< -o $@

clean:
	rm -f $(OBJ) $(BIN)

.PHONY: all clean

CXXFLAGS += -std=c++20 -Wno-deprecated-declarations

LDLIBS += -lssl -lcrypto
