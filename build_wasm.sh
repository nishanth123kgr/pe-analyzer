#!/bin/bash

# Build script for WebAssembly conversion of PE Analyzer

# Create output directory if it doesn't exist
mkdir -p wasm_build

# Clean previous build
rm -f wasm_build/pe_analyzer.js wasm_build/pe_analyzer.wasm

# Compile the main.c file to WebAssembly
emcc main.c \
  -o wasm_build/pe_analyzer.js \
  -s WASM=1 \
  -s EXPORTED_FUNCTIONS='["_malloc", "_free", "_analyze_pe_buffer"]' \
  -s EXPORTED_RUNTIME_METHODS='["ccall", "cwrap", "UTF8ToString"]' \
  -s ALLOW_MEMORY_GROWTH=1 \
  -s MODULARIZE=1 \
  -s EXPORT_NAME="PEAnalyzer" \
  -s ERROR_ON_UNDEFINED_SYMBOLS=0 \
  -s ASSERTIONS=1 \
  -s NO_EXIT_RUNTIME=1 \
  -O2

echo "Build completed. Output in wasm_build directory."
