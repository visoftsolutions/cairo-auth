# Cairo-Auth: Project Execution Instructions 🚀

Before you dive into the project, ensure that the necessary prerequisites are in place. This guide will walk you through each step of setting up and running the project.

## Prerequisites

1. **Python Environment**:
   - We highly recommend using `pyenv` for handling multiple Python versions. With `pyenv`, the required Python version will be selected automatically as per the `.python-version` file.
   - If not using `pyenv`, ensure that `Python 3.9.17` is installed on your system.

## Initial Setup

### Step 1: Create a Python virtual environment

```shell
python -m venv .venv
```

### Step 2: Activate the virtual environment

- On Unix or MacOS systems:

```shell
source .venv/bin/activate
```

- On Windows:

```shell
.venv\Scripts\activate
```

### Step 3: Install the necessary Python packages

```shell
pip install -r requirements.txt
```

### Step 4: Compile the CairoZero code

```shell
./scripts/1-compile.sh
```

### Step 5: Execute the CairoZero program to produce a trace

```shell
./scripts/2-run.sh
```

### Step 6: Generate a CairoZero proof from the trace

```shell
./scripts/3-prove.sh
```

### Step 7: Verify the generated proof

```shell
./scripts/4-verify.sh
```

## Minikube Environment Setup

### Step 1: Configure Minikube DNS

Set up the Minikube DNS environment on your machine to expose ingress hostnames. Refer to the official documentation here: [Minikube Ingress DNS Guide](https://minikube.sigs.k8s.io/docs/handbook/addons/ingress-dns/)

### Step 2: Configure DNS server

Update the `systemd-resolved` configuration to use `127.0.0.1` as your DNS server.
Edit the `resolved.conf` file.

#### **`/etc/systemd/resolved.conf`**

```
DNS=127.0.0.1
```

### Step 3: Start Minikube with necessary add-ons

```shell
minikube start --addons ingress,ingress-dns
```

### Step 4: Install cert-manager in your cluster

```shell
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.12.4/cert-manager.yaml
```

### Step 5: Deploy the server application

```shell
skaffold run
```

### Step 6: Access the Application

Open your preferred browser and navigate to the domain specified in the ingress, for example `https://cairo.test/`.
