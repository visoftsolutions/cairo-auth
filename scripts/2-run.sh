#!/bin/env bash

cairo-run \
    --program=artifacts/main_compiled.json \
    --layout=small \
    --program_input=src/main_input.json \
    --air_public_input=artifacts/main_public_input.json \
    --air_private_input=artifacts/main_private_input.json \
    --trace_file=artifacts/main_trace.bin \
    --memory_file=artifacts/main_memory.bin \
    --print_output \
    --proof_mode
