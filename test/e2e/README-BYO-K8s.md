# Running E2E Tests on GCE BYO K8s VM

These steps allow running the e2e test suite against a Kubernetes cluster on a GCE VM (bring-your-own K8s), instead of GKE.

## Prerequisites

- A running Kubernetes cluster on a GCE VM (or any VM) with `kubectl` configured and `KUBECONFIG` (or `~/.kube/config`) pointing at it.
- GCS FUSE CSI driver installed on the cluster (see project root for deployment), or use the script to install it (see below).
- GCP credentials available (e.g. `gcloud auth application-default login`) for the test process to create/delete GCS buckets and set IAM.
- Pods in the cluster must be able to authenticate to GCS (see [Auth](#auth) below).

## Required config (env vars)

Set **at least**:

| Variable | Required | Description |
|----------|----------|-------------|
| `E2E_GCP_PROJECT` | **Yes** | Your GCP project ID (used for metadata and GCS buckets). |

Optional:

| Variable | Default | Description |
|----------|---------|-------------|
| `E2E_CLUSTER_REGION` | `us-central1` | GCP region (used for metadata and bucket location). |
| `E2E_CLUSTER_NAME` | `byo-cluster` | Logical cluster name for metadata. |
| `GKE_CLUSTER_REGION` | `us-central1` | Used as `--test-bucket-location` and, when `E2E_GCP_PROJECT` is set, as `E2E_CLUSTER_REGION` default. |

## Run

**Option A: Driver already installed on the cluster**

```bash
export E2E_GCP_PROJECT=your-gcp-project-id
export E2E_TEST_SKIP_CSI_DRIVER_INSTALL=true
export E2E_TEST_USE_GKE_MANAGED_DRIVER=false
# Optional: export E2E_CLUSTER_REGION=us-central1
# Optional: export E2E_CLUSTER_NAME=my-cluster

./test/e2e/run-e2e-local.sh
```

**Option B: Let the script build and install the driver**

```bash
export E2E_GCP_PROJECT=your-gcp-project-id
export E2E_TEST_USE_GKE_MANAGED_DRIVER=false
export REGISTRY=gcr.io/your-project-id   # or another registry you can push to

./test/e2e/run-e2e-local.sh
```

## Auth

The tests create buckets and grant access using one of:

- **GKE Workload Identity**  
  If your BYO cluster uses Workload Identity (pool `PROJECT_ID.svc.id.goog`), the default test flow (with `--skip-gcp-sa-test=true`) will grant that identity access to the test buckets. No extra config needed beyond having WI set up.

- **GCP Service Account (no Workload Identity)**  
  If pods do not use Workload Identity, you must either:
  - Configure another way for the driver and test pods to get GCP credentials (e.g. node SA, or a secret with a key), and ensure the test-created buckets are accessible to that identity; or
  - Run with `--ginkgo-skip-gcp-sa-test=false` and ensure the test can create GCP service accounts and bind them (e.g. via a K8s SA with a GCP SA key in a secret) if that path is supported by your setup.

## Skipping tests that need internal resources

- **Profiles test** using the static bucket in project `gke-scalability-images`: do not enable profiles, or skip that test. Default runs do not enable `enable-gcsfuse-profiles`.
- **OIDC**: already skipped by default in the local script (`oidc` in `E2E_TEST_SKIP`).

## Data/info you need

To execute the test on a GCE BYO K8s VM you need:

1. **GCP project ID** – set `E2E_GCP_PROJECT`.
2. **kubeconfig** – current context must point at your cluster (no specific context name required when `E2E_GCP_PROJECT` is set).
3. **Cluster version** – the script infers it from `kubectl version`; ensure `kubectl` is in `PATH` and points at your cluster.
4. **GCP auth** – application default credentials (or equivalent) for the test process to create/delete GCS buckets and IAM.
5. **Pod → GCS auth** – Workload Identity or another mechanism so that pods can access GCS (see [Auth](#auth) above).
