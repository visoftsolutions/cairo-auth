#!/bin/env bash

mkdir -p artifacts
cairo-compile src/main.cairo --output artifacts/main_compiled.json --proof_mode
