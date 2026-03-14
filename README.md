# external-dns-technitium-webhook

> [!WARNING]
> This is homelab quality software, and not meant for production usage. You have been warned.

External-dns-technitium-webhook is an [ExternalDNS](https://kubernetes-sigs.github.io/external-dns/latest/) webhook to
integrate it with [Technitium DNS](https://technitium.com/dns/).

## Usage

The application expects all configuration to be passed in via environment variables.

| Environment Variable  | Description                                                                                                      |
|-----------------------|------------------------------------------------------------------------------------------------------------------|
| `LISTEN_ADDRESS`      | The address the webhook server binds to (defaults to `0.0.0.0`).                                                 |
| `LISTEN_PORT`         | The port the webhook server listens on (defaults to `3000`).                                                     |
| `TECHNITIUM_URL`      | The URL of the Technitium DNS server (required).                                                                 |
| `TECHNITIUM_USERNAME` | The username to authenticate with the Technitium DNS server (required).                                          |
| `TECHNITIUM_PASSWORD` | The password to authenticate with the Technitium DNS server (required).                                          |
| `ZONE`                | The primary zone to manage (e.g. `example.com`, required).                                                       |
| `ZONES`               | A comma-separated list of all zones to manage (e.g. `example.com,other.com`, defaults to the value of `ZONE`).  |
| `DOMAIN_FILTERS`      | A semicolon-separated list of domain filters to return during ExternalDNS negotiation (optional, defaults to the value of `ZONES`). |

### Zone Handling

On startup, the webhook checks each zone listed in `ZONES` and creates any that don't exist in Technitium DNS.

Zones are created as Conditional Forwarder type, with forwarder set to `this-server` and DNSSEC validation enabled.
This provides split-horizon DNS behaviour: records added by ExternalDNS are served locally, while any record not
present in the zone is forwarded to the DNS server's upstream resolver (e.g. Cloudflare DoH). This means external
records such as MX, VPN entries, and domains pointing to third-party services continue to resolve correctly from
inside the network.

## Example Kubernetes Deployment

When deploying on kubernetes, the Technitium DNS webhook can be deployed as a sidecar to the external-dns deployment.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: external-dns-technitium-dns
  namespace: external-dns
  labels:
    app.kubernetes.io/name: external-dns
spec:
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app.kubernetes.io/name: external-dns
  template:
    metadata:
      labels:
        app.kubernetes.io/name: external-dns
    spec:
      serviceAccountName: external-dns
      containers:
        - name: external-dns
          image: registry.k8s.io/external-dns/external-dns
          args:
            - --source=service
            - --source=ingress
            - --registry=noop
            - --provider=webhook
            - --webhook-provider-url=http://localhost:5580
        - name: webhook
          image: ghcr.io/gronare/external-dns-technitium-webhook
          env:
            - name: RUST_LOG
              value: "external_dns_technitium_webhook=info"
            - name: LISTEN_PORT
              value: "5580"
            - name: TECHNITIUM_URL
              value: "http://technitium-dns-dashboard.dns.svc.cluster.local:5380"
            - name: ZONE
              value: "example.com"
            - name: ZONES
              value: "example.com,other.com"
          envFrom:
            - secretRef:
                name: technitium-dns
          resources:
            requests:
              cpu: 1m
              memory: 10Mi
          readinessProbe:
            httpGet:
              port: 5580
              path: /health
            failureThreshold: 1
---
kind: Secret
type: Opaque
apiVersion: v1
stringData:
  TECHNITIUM_USERNAME: admin
  TECHNITIUM_PASSWORD: admin
metadata:
  name: technitium-dns
  namespace: external-dns
```
