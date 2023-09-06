#!/bin/env bash

./bin/cpu_air_prover \
    --out_file=artifacts/main_proof.json \
    --private_input_file=artifacts/main_private_input.json \
    --public_input_file=artifacts/main_public_input.json \
    --prover_config_file=config/cpu_air_prover_config.json \
    --parameter_file=config/cpu_air_params.json
