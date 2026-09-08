# HashiCorp Health Check

An interactive health check for **HashiCorp Vault** and **Terraform**, covering both the managed
(**HCP Vault Dedicated**, **HCP Terraform**) and self-managed (**Vault Enterprise**, **Terraform
Enterprise**) editions. It captures a customer's deployment against HashiCorp best practices, tags
each control by who owns it under the relevant responsibility model, and produces a remediation
report ranked by severity with proof-of-concept recommendations for capabilities the customer has
not adopted.

The app is a single static page. It runs entirely in the browser with no backend and no external
network calls. React and the official HashiCorp, Vault, and Terraform logos are bundled into the
image at build time, so nothing is fetched at runtime.

## Requirements

Docker or Podman. Nothing else. The build compiles the app inside the image, so you do not need
Node.js on the host.

## Build and run

### Docker

```bash
docker build -t hashicorp-health-check .
docker run --rm -p 8080:80 hashicorp-health-check
```

### Podman

```bash
podman build -t hashicorp-health-check .
podman run --rm -p 8080:80 hashicorp-health-check
```

Then open http://localhost:8080. Change the host port by editing the left side of `-p`.

## Deployment model

Set the **Vault deployment** and **Terraform deployment** independently in the left panel, so one
assessment can describe a mixed estate (for example HCP Vault Dedicated alongside a self-hosted
Terraform Enterprise).

- **HCP (managed).** Platform, storage, seal/unseal, and network controls are HashiCorp-managed and
  shown as informational, out of the score. You assess the logical configuration (auth, policies,
  secrets engines) plus audit and metrics streaming.
- **Enterprise (self-managed / self-hosted).** Those platform, seal, and network controls return to
  you and are scored, the root-token, audit-device, and telemetry controls take their self-managed
  wording, and edition-specific controls appear: Vault replication, namespaces, seal wrap / HSM,
  control groups, and Sentinel policies; Terraform Enterprise adds a self-hosted operations domain
  (host hardening, TLS, PostgreSQL, object storage, backups/DR, the encryption password, upgrades,
  and admin exposure).

The **Cloud** selector filters cloud-specific controls (IMDSv2 on AWS, Entra ID on Azure).

## Using it

- Set the customer, assessor, deployments, and cloud in the left panel.
- Work through each domain. For each control, mark it In use / Not implemented / N/A. When it is in
  use, tick the best-practice criteria it meets; the system derives alignment (under a third of
  criteria ticked reads as Not aligned, a third or more as Partial, all as Fully aligned).
- PKI, Transit, and Kubernetes are optional capabilities. Mark one not implemented to skip its
  controls; the report then recommends a proof-of-concept instead of flagging gaps.
- Switch to **Report** for the ranked findings and a **Save as PDF / Print** button. The report
  header carries the official HashiCorp, Vault, and Terraform marks.

### Saving work

**Save** downloads the whole assessment as a JSON file; **Load** restores it. There is no
server-side storage, so the container holds no customer data. Assessments saved by the previous
(HCP-only) version load correctly and default both deployments to HCP.

## Modifying the control set

Controls, severities, responsibility tags, and per-deployment variants live in `src/App.jsx` (the
`CONTROLS` and `DOMAINS` arrays). A control that differs by deployment carries a `variants` map;
edition-specific controls carry `appliesTo`. Edit that file and rebuild the image.

## Layout

```
Dockerfile          multi-stage build: bundle with esbuild, serve with nginx
nginx.conf          static serving config
build.mjs           esbuild bundle script (React vendored in, automatic JSX, no CDN)
public/index.html   HTML shell
src/App.jsx         the app, the full control dataset, and the inlined logos
src/main.jsx        React entry point
```
