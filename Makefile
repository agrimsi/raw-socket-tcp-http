CXX      := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2
LDFLAGS  :=

SRCDIR   := src
BUILDDIR := build

SRCS := $(SRCDIR)/raw_socket.cpp \
        $(SRCDIR)/ipv4.cpp \
        $(SRCDIR)/tcp.cpp \
        $(SRCDIR)/tcp_connection.cpp

OBJS := $(patsubst $(SRCDIR)/%.cpp,$(BUILDDIR)/%.o,$(SRCS))

# Client and server have their own main files.
CLIENT_SRC := $(SRCDIR)/client_main.cpp
SERVER_SRC := $(SRCDIR)/server_main.cpp

CLIENT_BIN := build/http_client
SERVER_BIN := build/http_server

.PHONY: all clean

all: $(CLIENT_BIN) $(SERVER_BIN)

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp | $(BUILDDIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(CLIENT_BIN): $(OBJS) $(BUILDDIR)/client_main.o
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

$(SERVER_BIN): $(OBJS) $(BUILDDIR)/server_main.o
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

$(BUILDDIR)/client_main.o: $(CLIENT_SRC) | $(BUILDDIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILDDIR)/server_main.o: $(SERVER_SRC) | $(BUILDDIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILDDIR)
