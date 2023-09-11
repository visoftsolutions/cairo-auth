#!/bin/env bash

mkdir -p artifacts
cairo-compile src/request.cairo --output artifacts/request_compiled.json --proof_mode
cairo-run \
    --program=artifacts/request_compiled.json \
    --layout=small \
    --program_input=src/request_input.json \
    --air_public_input=artifacts/request_public_input.json \
    --air_private_input=artifacts/request_private_input.json \
    --trace_file=artifacts/request_trace.bin \
    --memory_file=artifacts/request_memory.bin \
    --print_output \
    --proof_mode
