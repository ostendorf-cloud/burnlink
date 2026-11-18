# burnlink

Helm chart for burnlink: a Go service serving an embedded Vue single page application, with
health, readiness and metrics on a second, administrative listener.

## Install

```sh
helm install burnlink charts/burnlink --set config.store.addr=dragonfly:6379
```

## Values

| Key | Description | Default |
| --- | --- | --- |
| `replicaCount` | Number of pod replicas | `1` |
| `image.repository` | Container image | `ghcr.io/ostendorf-cloud/burnlink` |
| `image.tag` | Image tag, defaults to the chart's `appVersion` | `""` |
| `service.port` | Public HTTP port | `8080` |
| `service.adminPort` | Admin port: health, readiness, metrics | `8081` |
| `ingress.enabled` | Expose the public port through an Ingress | `false` |
| `httpRoute.enabled` | Expose the public port through a Gateway API HTTPRoute | `false` |
| `config.store.addr` | Store address, `host:port`, wired into `STORE_ADDR`. Required | `""` |
| `config.store.tls` | Connect to the store over TLS, wired into `STORE_TLS` | `false` |
| `existingSecret.name` | Existing Secret holding the store credentials | `""` |
| `existingSecret.usernameKey` | Key of the store username in that Secret | `""` |
| `existingSecret.passwordKey` | Key of the store password in that Secret | `""` |
| `config.trustedProxyCidrs` | CIDRs whose `X-Forwarded-For` entry is trusted, wired into `TRUSTED_PROXY_CIDRS` | `""` |

`ingress.enabled` and `httpRoute.enabled` are mutually exclusive: enabling both fails the
render. Neither routes to the admin port; that stays cluster-internal.

Rendering with `ingress.enabled` true and `config.trustedProxyCidrs` left empty also fails the
render: left unset behind this chart's own Ingress, the client address resolution that setting
feeds collapses every submitter onto the ingress controller's own pod address. Set it to the
ingress controller's pod or Service CIDR.

`config.store.addr` is required: the render fails without it. The chart deploys no store. Point
it at a Redis-compatible server, for example Dragonfly, that speaks `SET NX PX` and `GETDEL`. The
pod reports unready while that store is unreachable.

The store's credentials live in a Secret you create yourself. The chart never renders one from
plaintext values. Set `existingSecret.name` and the key names, and the Secret is mounted as
files, wired into `STORE_USERNAME_FILE` and `STORE_PASSWORD_FILE`:

```sh
helm install burnlink charts/burnlink \
  --set config.store.addr=dragonfly:6379 \
  --set existingSecret.name=burnlink-store \
  --set existingSecret.passwordKey=password
```

## Verification

```sh
task lint:helm
task validate:kubeconform
task test:helm
```
