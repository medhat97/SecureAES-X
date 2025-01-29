CC = gcc
CFLAGS = -Wall -Wextra -I./include -O2
SRC_DIR = src
OBJ_DIR = bin
TEST_DIR = tests
BIN_DIR = bin

# Source files
SRC_FILES = $(SRC_DIR)/aes_core.c $(SRC_DIR)/gcm.c
OBJ_FILES = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRC_FILES))

# Test programs
TEST_PROGRAMS = aes_ecb_demo aes_gcm_demo benchmark_speed_test test-vectors

.PHONY: all clean tests

all: $(OBJ_FILES) tests

# Create object directory if it doesn't exist
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# Compile source files to object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Build test programs
tests: $(TEST_PROGRAMS)

$(TEST_PROGRAMS): %: $(TEST_DIR)/%.c $(OBJ_FILES)
	$(CC) $(CFLAGS) $< $(OBJ_FILES) -o $(BIN_DIR)/$@

clean:
	rm -f $(OBJ_DIR)/*.o $(BIN_DIR)/*
	
# Individual test targets for convenience
aes_ecb_test: $(BIN_DIR)/aes_ecb_demo
	./$(BIN_DIR)/aes_ecb_demo

aes_gcm_test: $(BIN_DIR)/aes_gcm_demo
	./$(BIN_DIR)/aes_gcm_demo

benchmark: $(BIN_DIR)/benchmark_speed_test
	./$(BIN_DIR)/benchmark_speed_test

test_vectors: $(BIN_DIR)/test-vectors
	./$(BIN_DIR)/test-vectors
