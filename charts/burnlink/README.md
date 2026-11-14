# burnlink

Helm chart for burnlink: a Go service serving an embedded Vue single page application, with
health, readiness and metrics on a second, administrative listener.

## Install

```sh
helm install burnlink charts/burnlink
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

`ingress.enabled` and `httpRoute.enabled` are mutually exclusive: enabling both fails the
render. Neither routes to the admin port; that stays cluster-internal.

`config` and `existingSecret` exist in the values shape but carry no properties yet: this
version of burnlink has no configuration surface and no secret-shaped environment variable. Both
arrive with the store client in a later milestone.

## Verification

```sh
task lint:helm
task validate:kubeconform
task test:helm
```
