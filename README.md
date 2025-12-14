# Cloud Naswail  — Full Project Documentation

## 1. Project overview

This repository provides a containerised IDS (Intrusion Detection System) API that exposes two detection backends:

* **ML detector** — legacy machine-learning flow-level detector (loaded from `scripts/ml_ids_deployment_original.py`).
* **DL detector** — deep-learning autoencoder-based anomaly detector (loaded from `scripts/dl_ids_deployment_fixed.py`).

A Flask API (`api_server_with_results.py`) exposes endpoints to submit either prebuilt PCAP content or lists of raw packet bytes (base64) for analysis. The project is designed to run inside Docker and to be deployed on cloud infrastructure (the original intent: Huawei Cloud). The Docker image packages models, runtime scripts, and a small management wrapper.

---

## 2. High-level architecture and runtime flow

1. Container starts and Flask app (`api_server_with_results.py`) runs.
2. On start, `IDSAPI.load_detectors()` attempts to import and instantiate the ML and DL detector classes from `/opt/ids-detector/scripts/`.

   * The ML detector is expected to provide a `bootstrap(data)` method that accepts a payload (PCAP content or filename+content) and returns a structured dict with `total_flows`, `benign_flows`, and `attacks`.
   * The DL detector is expected to provide a `bootstrap(data)` method that returns `total_flows`, `benign_flows`, and `anomaly_flows`.
3. API endpoints accept JSON payloads, convert packet raw bytes (base64) into a temporary PCAP if needed (using `scapy`), and pass the resulting content to the chosen detector's `bootstrap`.
4. Results are normalized into a predictable JSON response and returned to the client.

---

## 3. Files and purpose (file-by-file)

### `Dockerfile`

Key points:

* Base image: `python:3.9-slim`.
* Installs system deps: `build-essential` (compilation tools) and `libpcap-dev` (required by scapy/nfstream).
* Copies `requirements.txt` and runs `pip install -r requirements.txt`.
* Creates directories under `/opt/ids-detector` then copies `scripts/` and `models/` into that location.
* Copies `api_server_with_results.py`, `api_server.py`, `credentials.csv`, `manage_ids.sh`.
* Exposes port `8080`.
* Entrypoint runs `python api_server_with_results.py`.

Notes / recommended improvements (expanded later): run as non-root, multi-stage build to reduce size, use pinned dependency versions.

---

### `api_server_with_results.py`

Primary Flask application. Key behaviors:

* Adds `/opt/ids-detector/scripts` to `sys.path` so detectors located under `scripts/` can be imported.
* `IDSAPI` class:

  * `load_detectors()` tries to import:

    * `ml_ids_deployment_original.ML_IDS` with signature `ML_IDS(arg1, arg2)` — instantiates with dummy args.
    * `dl_ids_deployment_fixed.AEAnomalyDetector(...)` with explicit file paths for model, error thresholds (`all_error.pkl`) and scaler (`scaler.pkl`).
  * Keeps instantiated `ml_detector` and `dl_detector`.
* Endpoints:

  * `GET /health` — returns JSON with `status` and booleans `ml_loaded`, `dl_loaded`.
  * `POST /detect/ml` — expects JSON body containing `content` (base64 PCAP) or a structure the ML detector accepts; calls `ml_detector.bootstrap(data)`; returns a normalized summary and detailed results grouped by attack type. On errors, returns HTTP 500 with error and traceback.
  * `POST /detect/dl` — similar to ML endpoint but for DL detector, expects `content` and returns anomalies.
  * `POST /detect/ml/packets` — expects `packets` (list of base64-encoded packet bytes). Reconstructs `scapy` `Ether(...)` packets, writes to a temporary file under `/tmp`, encodes the PCAP to base64, then calls `ml_detector.bootstrap({ "filename": "converted.pcap", "content": pcap_b64 })`.
  * `POST /detect/dl/packets` — same as ML packets endpoint but calling `dl_detector.bootstrap(...)`.
* Error handling: exceptions are returned with `traceback.format_exc()` (useful for debugging but avoid in production — leaking stack traces).

Important assumptions:

* The `bootstrap` interface for both detectors returns dictionaries with specific keys used by the API to produce the final JSON. If the detector code deviates, the API will raise errors or return partial results.
* `scapy` is present in the environment (installed via `requirements.txt`).

---

### `manage_ids.sh`

Simple management script for a VM host (non-container):

* `start` — `screen -dmS ids-api python3 api_server_with_results.py`
* `stop` — kills screen session and `python3` process.
* `restart`, `status` implemented.
  Notes:
* For containerized deployment, use Docker/Kubernetes control instead of `screen`.
* `screen` commands imply intended run on a Linux VM (ECS instance) rather than containerized orchestrator.

---

### `req.txt` (requirements)

Core runtime Python packages:

* `flask`, `pandas`, `numpy`, `scikit-learn`, `torch`, `torchvision`, `joblib`, `scapy`, `nfstream`, `gunicorn`, `requests`, `psutil`

Notes:

* Pin exact versions in `requirements.txt` for reproducibility.
* `torch`+`torchvision` require special care if GPU acceleration is used (will need matching CUDA and a different base image).

---

### `test.py`

Local client/monitor that:

* Captures live packets using `scapy.sniff(filter="ip", timeout=CAPTURE_DURATION)`.
* Converts each captured packet to raw bytes and base64-encodes them into a list.
* Posts the list to `/detect/ml/packets` and `/detect/dl/packets`.
* Logs aggregated detection results to a local log file `ids_detections.log`.
* Prints human-friendly summaries and first N anomalies for inspection.

This script is a simple end-to-end test harness for the deployed API.

---

## 4. Detectors interface (expected)

The API assumes detectors expose a `bootstrap(data: dict) -> dict` method. Expected response shapes (as used by the Flask app):

### ML detector (`ml_detector.bootstrap(data)`)

Return example:

```json
{
  "total_flows": 100,
  "benign_flows": 95,
  "attacks": {
    "PORT_SCAN": {
      "count": 3,
      "flows": [
        {
          "index": 12,
          "src_ip": "10.0.0.1",
          "dst_ip": "10.0.0.2",
          "src_port": 3456,
          "dst_port": 80,
          "protocol": 6,
          "attack": "PORT_SCAN"
        }
      ]
    },
    "DNS_AMP": {
      "count": 2,
      "flows": [...]
    }
  }
}
```

### DL detector (`dl_detector.bootstrap(data)`)

Return example:

```json
{
  "total_flows": 100,
  "benign_flows": 98,
  "anomaly_flows": {
    "count": 2,
    "flows": [
      {
        "index": 45,
        "src_ip": "10.0.0.3",
        "dst_ip": "8.8.8.8",
        "src_port": 12345,
        "dst_port": 53,
        "protocol": 17,
        "reconstruction_error": 0.12
      }
    ]
  }
}
```

If a detector returns `{"error": ...}` the API forwards it as a 500.

---

## 5. API Reference (examples)

### Health

* `GET /health`
* Response:

```json
{
  "status": "healthy",
  "ml_loaded": true,
  "dl_loaded": true
}
```

### ML detection (prebuilt PCAP/flow payload)

* `POST /detect/ml`
* Body: JSON containing the same structure the ML detector accepts. Minimal required: `{ "content": "<base64-pcap>" }`
* Successful response: normalized summary and `detailed_results` keyed by `<attacktype>_flows`.

### DL detection (prebuilt PCAP/flow payload)

* `POST /detect/dl`
* Body: `{ "content": "<base64-pcap>" }`
* Successful response: summary + `detailed_results.anomaly_flows`.

### ML detection from packets

* `POST /detect/ml/packets`
* Body:

```json
{
  "packets": ["<base64-pkt1>", "<base64-pkt2>", ...]
}
```

* The server reconstructs packets with scapy, writes a temp PCAP, base64-encodes it and passes to ML detector.

### DL detection from packets

* `POST /detect/dl/packets`
* Body: same as ML packets endpoint.
* Behavior mirrors ML packets endpoint.

### Example cURL (packets)

```bash
curl -X POST "http://<host>:8080/detect/ml/packets" \
  -H "Content-Type: application/json" \
  -d '{"packets":["<base64pkt1>","<base64pkt2>"]}'
```

---

## 6. Deployment guides

### Local Docker

1. Build:

```bash
docker build -t ids-detector:latest -f Dockerfile .
```

2. Run:

```bash
docker run --rm -p 8080:8080 --name ids-detector ids-detector:latest
```

3. Verify:

```bash
curl http://localhost:8080/health
```

### Production container runtime (recommended improvements)

* Use `gunicorn` with a WSGI entrypoint to run Flask in production (multi-worker).
* Example `CMD`:

```bash
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8080", "api_server_with_results:app"]
```

* Set `timeout`, proper logging, and keep stdout/stderr for container logs.

### Huawei Cloud — recommended deployment approaches

(These are deployment *patterns*; adapt to your organization’s preferred services.)

#### Option A — Elastic Cloud Server (ECS) + Docker

* Build the Docker image locally or in CI.
* Push image to a container registry (SWR or an object storage + registry).
* Provision an ECS instance (choose appropriate CPU & memory; for DL inference, use GPU-enabled instance if the model requires CUDA).
* Pull and run the container on ECS.
* Attach a security group rule to allow inbound traffic on port 8080 (or place the container behind a load balancer).
* Use systemd / docker-compose to manage lifecycle, or use the provided `manage_ids.sh` if running directly on the host (note: `manage_ids.sh` uses `screen` and `python3` — not needed when running containers).

#### Option B — Container Service (CCE / Kubernetes)

* Push the image to a registry (SWR).
* Deploy a Kubernetes Deployment and Service.
* Use Horizontal Pod Autoscaler to scale pods horizontally by CPU or custom metrics.
* For DL models that need GPUs, schedule pods on GPU node pools and build images with appropriate CUDA / cuDNN libraries.

#### Option C — Managed model deployment (ModelArts) — optional

* If you want managed model serving (scalable inference) and model lifecycle, consider deploying the DL model with a managed model-serving product.
* Export the model artifacts (`.pth`, scalers, pickles) to object storage (OBS) and use the managed serve functionality to host inference, then call that endpoint from your API server (which remains a thin wrapper).

#### Storage of large model artifacts

* Store model files in persistent object storage (OBS) or SWR artifact storage; mount or download them at container start.
* Paths in `api_server_with_results.py` assume models present at `/opt/ids-detector/models/dl_models/...` inside container. To change this, use environment variables.

---

## 7. Practical improvements & hardening (recommended)

### Docker / image improvements

* Use multi-stage builds and a smaller runtime image (e.g., `python:3.9-slim` final but compile build deps in a builder stage).
* Create a non-root user and `USER` in Dockerfile.
* Avoid copying raw credentials (`credentials.csv`) into image; use secrets or environment variables instead.
* Pin package versions in `requirements.txt` (e.g., `flask==2.2.3`) for reproducibility.

### Configuration

* Use environment variables for:

  * Model paths (`ML_MODEL_PATH`, `DL_MODEL_PATH`, `SCALER_PATH`)
  * Logging level
  * Host/port override
* Provide a small `config.py` that reads env vars and falls back to the current defaults.

### Security

* Add authentication on API endpoints (API keys, mTLS, JWT).
* Never expose internal diagnostic tracebacks to unauthorised clients in production.
* Terminate TLS at ingress (load balancer / reverse proxy) and use HTTPS.
* Rate-limit detection endpoints (to avoid DoS by large packet uploads).
* Validate and limit size of incoming payloads (max number of packets, max PCAP size).

### Reliability & scaling

* Use process manager (gunicorn) with multiple workers — CPU-bound tasks (scapy parsing, nfstream) should be considered when sizing worker counts.
* Offload heavy preprocessing to background workers or queue (e.g., RabbitMQ/Redis + worker pool) if synchronous API latency is unacceptable.
* For DL inference, run model serving on GPU-enabled hosts or use a separate scaled inference service.

### Observability

* Replace `print()` logs with structured logging (JSON) and ship logs to a logging backend or cloud logging service.
* Expose Prometheus metrics:

  * counters: total requests, total anomalies detected
  * histograms: request durations, pcap conversion latency
* Keep `/health` as liveness/ readiness probe for orchestrators.

---

## 8. Testing, validation, and QA

### Unit/integration tests

* Create unit tests for:

  * Packet -> PCAP conversion function (mock scapy Ether creation).
  * Detector `bootstrap` adapter wrapper (simulate detector returning specific shapes).
  * API endpoints using Flask test client (POST/GET).
* Use CI to run tests on each commit and to build Docker image.

### Reproducible test data

* Store small test PCAP files or fixture base64 blobs in a `tests/fixtures` folder.
* Use `test.py` as an integration test but adapt it to have a “dry-run” mode that reads PCAPs from fixture files instead of capturing live traffic.

### Performance testing

* Load test `/detect/*/packets` endpoints with realistic batch sizes to measure CPU, memory, and pcap conversion overhead. Tools: `locust`, `ab`, or `wrk`.

---

## 9. Troubleshooting & common failure modes

### `scapy` import errors inside Docker

Cause: missing `libpcap-dev` or other binary dependencies. Fix: ensure `libpcap-dev` is installed in image (already present in Dockerfile). Confirm correct Python version and that `scapy` installed in `pip`.

### Detector failing to load on startup

* Check absolute paths used in `AEAnomalyDetector` instantiation; ensure model files exist inside the container at those paths.
* If detectors expect CUDA and `torch.cuda.is_available()` is True/False mismatch, ensure correct Torch build for environment.

### Large PCAPs consuming memory/disk

* Temporary file creation uses `/tmp`. Ensure `/tmp` has sufficient space, or use streamed approaches rather than writing full PCAPs to disk.
* Implement maximum allowed PCAP size and return error when exceeded.

### API times out on large uploads

* Increase server timeout and/or move the heavy work to an asynchronous worker pipeline with a job id response.

### `manage_ids.sh` not applicable inside container

* The script is for VM-hosted Python run. For containerized deployment, use `docker` commands, systemd unit (if using `podman` or bare host), or Kubernetes controllers.

---

## 10. Example operational commands

Build & push (generic):

```bash
docker build -t myregistry.example.com/ids-detector:1.0 .
docker push myregistry.example.com/ids-detector:1.0
```

Run with mounted models (if you prefer not to bake models into image):

```bash
docker run --rm -p8080:8080 \
  -v /host/models:/opt/ids-detector/models:ro \
  -e ML_MODEL_PATH=/opt/ids-detector/models/ml_models/model.pkl \
  myregistry.example.com/ids-detector:1.0
```

Gunicorn run (recommended for production):

```bash
gunicorn -w 4 -k gthread -b 0.0.0.0:8080 api_server_with_results:app
```

Kubernetes (minimal Deployment + Service, adapt for CCE):

```yaml
# Deployment (snippet)
apiVersion: apps/v1
kind: Deployment
metadata: { name: ids-detector }
spec:
  replicas: 2
  selector: { matchLabels: { app: ids-detector } }
  template:
    metadata: { labels: { app: ids-detector } }
    spec:
      containers:
      - name: ids
        image: myregistry/ids-detector:1.0
        ports: [{ containerPort: 8080 }]
        readinessProbe:
          httpGet: { path: /health, port: 8080 }
          initialDelaySeconds: 10
          periodSeconds: 10

# Service (snippet)
apiVersion: v1
kind: Service
metadata: { name: ids-service }
spec:
  selector: { app: ids-detector }
  ports:
  - port: 80
    targetPort: 8080
  type: LoadBalancer
```

---
