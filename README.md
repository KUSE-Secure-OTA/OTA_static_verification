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

## 🔁 Execution Flow Summary
```text
static/images/*.tar
        ↓ (podman load)
OCI image
        ↓ (podman save --format docker-archive)
*.docker.tar
        ↓ (run_all.sh)
static_out/<image_version>/
        ├─ policy.log
        ├─ sbom.json
        ├─ secret.json
        ├─ license.json
        └─ fs.json
```

## 📦 Image Input & Output Convention
### ✔️ Input image location
Place pre-built OCI image archives (`.tar`) under the `static/images/` directory.
Each image represents an independent attack scenario used for static verification.

### ✔️ Image format conversion (OCI → docker-archive)
The static verification pipeline operates on the `docker-archive` format internally.
Therefore, each experiment follows this process:
1. Load the OCI image using `podman load`
2. Re-export the image as `docker-archive` using `podman save --format docker-archive`
3. Pass the converted `.docker.tar` file to `run_all.sh` for static verification

### ✔️ Verification output location
All static verification artifacts (logs, policy decisions, and scanner outputs) are written to `static_out/<image_version>/.`


## ⚙️ Static Verification Commands (Per Image)
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

## 📊 Expected Verification Outcomes (Examples)
The following outputs show **representative examples** of `policy.log` for each image.
They illustrate the **expected policy decisions** of the static verification pipeline.
* Images **ivi_2.3.1–ivi_2.3.4** are **intentionally designed to FAIL**
due to explicit policy violations.
* Image **ivi_2.3.5** is expected to **PASS with warnings**, as it contains
outdated or vulnerable packages but no hard policy violations.

### ✔️ Expected Results Summary
| Image Version | Scenario Type        | Expected Result   | Primary Failure Reason                |
| ------------- | -------------------- | ----------------- | ------------------------------------- |
| `ivi_2.3.1`   | Forbidden components | **FAILED**        | Forbidden SBOM component (`tcpdump`)  |
| `ivi_2.3.2`   | Secret leakage       | **FAILED**        | Secrets detected in filesystem        |
| `ivi_2.3.3`   | Malicious build      | **FAILED**        | Suspicious ENTRYPOINT / build history |
| `ivi_2.3.4`   | Disallowed license   | **FAILED**        | AGPL license + forbidden component    |
| `ivi_2.3.5`   | Outdated packages    | **PASSED (WARN)** | CVEs and license warnings only        |
