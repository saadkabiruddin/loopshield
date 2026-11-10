# Host-side tests for the firmware's pure-C modules.
#   make test     unit tests for the protocol checks
#   make sim      closed-loop detector simulation (./sim --help-ish flags in sim.c)
CFLAGS = -O2 -Wall -Wextra -I../main
OUT ?= build

all: test sim

$(OUT):
	mkdir -p $(OUT)

$(OUT)/test_proto: test_proto.c ../main/sg_proto.c ../main/sg_msg.c | $(OUT)
	$(CC) $(CFLAGS) $^ -o $@

$(OUT)/sim: sim.c ../main/sg_detect.c ../main/sg_pi.h | $(OUT)
	$(CC) $(CFLAGS) sim.c ../main/sg_detect.c -lm -o $@

test: $(OUT)/test_proto
	./$(OUT)/test_proto

sim: $(OUT)/sim
	./$(OUT)/sim

.PHONY: all test sim

# Shared library for the host stand-in controller (hostctl/).
$(OUT)/libsghost.so: hostlib.c ../main/sg_proto.c ../main/sg_msg.c ../main/sg_detect.c | $(OUT)
	$(CC) $(CFLAGS) -fPIC -shared $^ -lm -o $@

hostlib: $(OUT)/libsghost.so

.PHONY: hostlib

# Protocol state-machine search (stretch goal).
$(OUT)/proto_search: proto_search.c ../main/sg_proto.c ../main/sg_msg.c | $(OUT)
	$(CC) $(CFLAGS) $^ -o $@

search: $(OUT)/proto_search
	./$(OUT)/proto_search

.PHONY: search
