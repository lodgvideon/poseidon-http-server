# Raw Kubernetes manifests

Helm-free manifests for `poseidon-server`, mirroring the Helm chart's secure
defaults for environments without Helm (or for `kubectl apply -f deploy/k8s/`).

Apply in order (or all at once — kubectl resolves ordering for these):

```sh
kubectl apply -f deploy/k8s/
```

## Probe choice (READ THIS)

The server speaks **HTTP/2 cleartext (h2c)** on port 8080, serving `/healthz`
and `/readyz` over that same h2c listener. Kubernetes `httpGet` probes speak
**HTTP/1.1** and will **not** complete an h2c handshake — a naive `httpGet`
probe fails against a perfectly healthy pod.

These manifests therefore use **`tcpSocket` probes** (a successful TCP accept
proves the listener is up). This is h2c-safe but not application-readiness-aware.
The codebase implements `grpc.health.v1` (`grpcserver/health.go`); once the
binary exposes a gRPC health listener you can switch to k8s native **`grpc:`**
probes (GA in 1.27+) for readiness-aware health. A commented `grpc:` block is
included in `deployment.yaml`.

## Image

Set the image in `deployment.yaml` (`ghcr.io/lodgvideon/poseidon-server:<tag>`)
before applying. Prefer an immutable tag or digest in production.
