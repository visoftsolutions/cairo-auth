# Project Execution Instructions 🚀

Ensure you have the prerequisites in place before you start.

## Prerequisites

- It's recommended to have `pyenv` installed. This will automatically select the right version of Python as defined in the `.python-version` file.
- Alternatively, ensure you have `Python 3.9.17` installed.

## Setup Steps

### 1. Create a Python virtual environment

```shell
python -m venv .venv
```

### 2. Activate the virtual environment

If you're on a Unix or MacOS system:

```shell
source .venv/bin/activate
```

For Windows:

```shell
.venv\Scripts\activate
```

### 3. Install the necessary Python packages

```shell
pip install -r requirements.txt
```

### 4. Compile the CairoZero code

```shell
./scripts/1-compile.sh
```

### 5. Run CairoZero program and produce a trace

```shell
./scripts/2-run.sh
```

### 6. Generate CairoZero proof from the trace

```shell
./scripts/3-prove.sh
```

### 7. Verify the generated proof

```shell
./scripts/4-verify.sh
```
