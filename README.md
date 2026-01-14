## ❗ Static Verification (Single Image Execution)
This directory provides a **standalone static verification workflow** for OTA container images.
Each image is verified **independently** to evaluate whether it violates predefined security and policy rules before deployment.

The verification pipeline checks:
- **SBOM-based forbidden components**
- **Secret leakage in filesystem**
- **Potentially malicious build patterns**
- **License policy violations**
- **Known CVEs (signal-only)**

All experiments below are executed using pre-built OCI images from the attack scenario repository.

### 1️⃣ ivi_2.3.1 (forbidden)
```bash
podman load -i static/images/ivi_2.3.1.tar && \
podman save --format docker-archive -o static/images/ivi_2.3.1.docker.tar localhost/ivi_forbidden:2.3.1 && \
bash static/run_all.sh static/images/ivi_2.3.1.docker.tar static_out/ivi_2.3.1
```

```bash
cat static_out/ivi_2.3.1/policy.log
```

### 2️⃣ ivi_2.3.2 (secret)
```bash
podman load -i static/images/ivi_2.3.2.tar && \
podman save --format docker-archive -o static/images/ivi_2.3.2.docker.tar localhost/ivi_secret:2.3.2 && \
bash static/run_all.sh static/images/ivi_2.3.2.docker.tar static_out/ivi_2.3.2
```

```bash
cat static_out/ivi_2.3.2/policy.log
```


### 3️⃣ ivi_2.3.3 (malicious)
```bash
podman load -i static/images/ivi_2.3.3.tar && \
podman save --format docker-archive -o static/images/ivi_2.3.3.docker.tar localhost/ivi_malicious:2.3.3 && \
bash static/run_all.sh static/images/ivi_2.3.3.docker.tar static_out/ivi_2.3.3
```

```bash
cat static_out/ivi_2.3.3/policy.log
```


### 4️⃣ ivi_2.3.4 (agpl)
```bash
podman load -i static/images/ivi_2.3.4.tar && \
podman save --format docker-archive -o static/images/ivi_2.3.4.docker.tar localhost/ivi_agpl:2.3.4 && \
bash static/run_all.sh static/images/ivi_2.3.4.docker.tar static_out/ivi_2.3.4
```

```bash
cat static_out/ivi_2.3.4/policy.log
```


### 5️⃣ ivi_2.3.5 (outdated)
```bash
podman load -i static/images/ivi_2.3.5.tar && \
podman save --format docker-archive -o static/images/ivi_2.3.5.docker.tar localhost/ivi_outdated:2.3.5 && \
bash static/run_all.sh static/images/ivi_2.3.5.docker.tar static_out/ivi_2.3.5
```

```bash
cat static_out/ivi_2.3.5/policy.log
```
