import { useState, useMemo, useRef, useEffect } from "react";

/* ------------------------------------------------------------------ *
 * HashiCorp Health Check
 * Scope: Vault (HCP Dedicated / Enterprise self-managed) and
 *        Terraform (HCP / Enterprise self-hosted), chosen per product.
 *
 * Model: each assessable control carries best-practice criteria. The
 * assessor ticks the ones the customer meets and the system derives
 * alignment from the fraction ticked:
 *   under 1/3 ticked  -> Not aligned
 *   1/3 to under all  -> Partial
 *   all ticked        -> Fully aligned
 *
 * Deployment: controls resolve against the selected deployment. A
 * control may carry per-deployment variants (responsibility, wording,
 * severity, criteria) and may appear only for some deployments via
 * appliesTo. Self-managed Vault Enterprise returns platform, seal,
 * and network controls to the customer and adds Enterprise-only
 * controls; Terraform Enterprise adds a self-hosted operations domain.
 *
 * Sources: customer Vault Enterprise Security Benchmark, plus authored
 * Terraform and self-hosted operations controls. First draft for review.
 * ------------------------------------------------------------------ */

const ONE_THIRD = 1 / 3;

const C = {
  ink: "#17181C", muted: "#5A6472", faint: "#8A93A2",
  line: "#E4E7EC", canvas: "#F5F6F8", panel: "#FFFFFF",
  primary: "#232A54", accent: "#4457C7", accentSoft: "#EEF0FB",
};
const SEV = {
  critical: { label: "Critical", fg: "#B42318", bg: "#FEE4E2", rank: 0 },
  high:     { label: "High",     fg: "#B54708", bg: "#FEF0C7", rank: 1 },
  medium:   { label: "Medium",   fg: "#175CD3", bg: "#E0EAFB", rank: 2 },
  low:      { label: "Low",      fg: "#475467", bg: "#EEF0F3", rank: 3 },
};
const RESP = {
  customer:  { label: "Customer",             fg: "#232A54", bg: "#E7E9F6" },
  shared:    { label: "Shared",               fg: "#175CD3", bg: "#E0EAFB" },
  hashicorp: { label: "Managed by HashiCorp", fg: "#475467", bg: "#EEF0F3" },
};
const ALIGN = {
  none:    { label: "Not aligned",   fg: "#B42318", bg: "#FEE4E2", score: 0 },
  partial: { label: "Partial",       fg: "#B54708", bg: "#FEF0C7", score: 0.5 },
  full:    { label: "Fully aligned", fg: "#067647", bg: "#E7F6EC", score: 1 },
};
/* Product colours (labels are deployment-aware via prodLabel). */
const PROD = {
  vault:     { fg: "#7A5B00", bg: "#FBEECB" },
  terraform: { fg: "#5B3EA6", bg: "#ECE4FA" },
};

const VAULT_DEPLOY = {
  hcp:        { label: "Vault Dedicated",  short: "HCP Dedicated" },
  enterprise: { label: "Vault Enterprise", short: "Enterprise (self-managed)" },
};
const TF_DEPLOY = {
  hcp:        { label: "HCP Terraform",       short: "HCP" },
  enterprise: { label: "Terraform Enterprise", short: "Enterprise (self-hosted)" },
};

function activeDeploy(product, meta) {
  return product === "vault" ? meta.vaultDeployment : meta.tfDeployment;
}
function prodLabel(product, meta) {
  return product === "vault"
    ? VAULT_DEPLOY[meta.vaultDeployment].label
    : TF_DEPLOY[meta.tfDeployment].label;
}

/* Adopt -> Standardize -> Scale maturity ladder. Stage is intrinsic to
   each control (keyed by id), deployment-independent, and counts only
   when the control is in scope for the gate. */
const STAGE_ORDER = ["adopt", "standardize", "scale"];
const MATURITY = {
  adopt:       { label: "Adopting",      short: "Adopt" },
  standardize: { label: "Standardizing", short: "Standardize" },
  scale:       { label: "Scaling",       short: "Scale" },
};
const MAT_DONE = "#22A366";   // completed stage
const MAT_NOW = C.accent;     // current stage
const MAT_NEXT = "#C4CAD4";   // not yet reached
const STAGE_TAGS = {
  "V-01": "adopt", "V-02": "adopt", "V-03": "adopt", "V-04": "adopt", "V-05": "adopt",
  "V-06": "adopt", "V-07": "standardize", "V-08": "adopt", "V-09": "adopt", "V-10": "standardize",
  "V-11": "adopt", "V-12": "standardize", "V-13": "standardize", "V-14": "standardize", "V-15": "scale",
  "V-16": "scale", "V-17": "scale", "V-18": "scale", "V-19": "scale",
  "V-20": "scale", "V-21": "scale", "V-22": "scale", "V-23": "scale",
  "V-24": "scale", "V-25": "scale", "V-26": "scale", "V-27": "scale", "V-28": "scale",
  "V-29": "adopt", "V-30": "scale", "V-31": "standardize", "V-32": "standardize", "V-33": "scale", "V-34": "scale",
  "V-39": "standardize", "V-40": "standardize", "V-41": "standardize", "V-42": "standardize",
  "V-43": "scale", "V-44": "scale", "V-45": "scale", "V-46": "standardize",
  "V-47": "scale", "V-48": "scale", "V-49": "scale", "V-50": "scale", "V-51": "scale",
  "T-01": "adopt", "T-02": "standardize", "T-03": "standardize", "T-04": "standardize",
  "T-05": "adopt", "T-06": "adopt", "T-07": "adopt", "T-08": "standardize", "T-09": "scale",
  "T-10": "standardize", "T-11": "scale", "T-12": "standardize", "T-13": "scale", "T-14": "scale",
  "T-15": "adopt", "T-16": "adopt", "T-17": "standardize", "T-18": "standardize", "T-19": "standardize",
  "T-20": "adopt", "T-21": "standardize", "T-22": "adopt",
};

/* Domains. product ties a domain to its deployment selector.
   capability:true -> whole domain can be marked not implemented (PoC).
   appliesTo limits a domain to certain deployments. */
const DOMAINS = [
  { id: "vault-platform", product: "vault", name: "Platform Hardening" },
  { id: "vault-auth", product: "vault", name: "Auth & Identity" },
  { id: "vault-secrets", product: "vault", name: "Secrets Engines" },
  { id: "vault-pki", product: "vault", name: "PKI", capability: true,
    poc: "Stand up a PKI intermediate in a non-prod namespace, issue a 24-hour certificate to one service, and automate renewal with Vault Agent." },
  { id: "vault-transit", product: "vault", name: "Transit", capability: true,
    poc: "Create one Transit key, encrypt and decrypt sample data as a service, and demonstrate key rotation without re-encrypting stored data." },
  { id: "vault-k8s", product: "vault", name: "Kubernetes", capability: true,
    poc: "Wire one non-prod namespace's service account to the Kubernetes auth method and inject a secret via the Vault Agent Injector." },
  { id: "vault-cloud", product: "vault", name: "Cloud & Network" },
  { id: "vault-mon", product: "vault", name: "Monitoring" },
  { id: "vault-dr", product: "vault", name: "Disaster Recovery" },
  { id: "vault-ent", product: "vault", name: "Enterprise Platform", appliesTo: ["enterprise"] },
  { id: "tf-access", product: "terraform", name: "Access & Governance" },
  { id: "tf-cred", product: "terraform", name: "Credentials & State" },
  { id: "tf-flow", product: "terraform", name: "Workflow & Change Control" },
  { id: "tf-policy", product: "terraform", name: "Policy as Code" },
  { id: "tf-mods", product: "terraform", name: "Modules & Supply Chain" },
  { id: "tf-agents", product: "terraform", name: "Connectivity & Agents" },
  { id: "tf-ops", product: "terraform", name: "Self-Hosted Operations", appliesTo: ["enterprise"] },
];
const DOMAIN_PRODUCT = Object.fromEntries(DOMAINS.map((d) => [d.id, d.product]));

/* Controls. Fields shared across deployments sit flat on the control.
   Where they differ, variants: { hcp:{...}, enterprise:{...} } override.
   resp: customer|shared|hashicorp. sev: null for managed/informational.
   optional:true -> "Not implemented" emits a PoC instead of a gap.
   cloud: null|aws|azure filters against the selected cloud.
   appliesTo: limits a control to certain deployments. */
const CONTROLS = [
  // ---- Vault: Platform Hardening ----------------------------------------
  { id: "V-01", d: "vault-platform", variants: {
      hcp: { t: "TLS in transit", resp: "hashicorp",
        desc: "HCP terminates and manages TLS on the cluster listeners and internal traffic.",
        note: "Clients still connect over the HTTPS cluster endpoint and must verify the certificate." },
      enterprise: { t: "Enable TLS everywhere", resp: "customer", sev: "high",
        desc: "Enable TLS on all listener and cluster/replication traffic and disable plaintext HTTP.",
        why: "Vault moves secrets, tokens, and unseal material over the network; without TLS an attacker can intercept or tamper with it.",
        criteria: [
          "tls_disable is false on every listener",
          "tls_cert_file and tls_key_file are set with valid certificates",
          "tls_min_version is tls12 or higher and weak ciphers are disabled",
          "TLS is enabled on the cluster/replication port, not only the API port",
          "Server certificates are issued and rotated by a CA or Vault PKI",
        ] },
    } },
  { id: "V-02", d: "vault-platform", variants: {
      hcp: { t: "Integrated storage (Raft)", resp: "hashicorp",
        desc: "HCP runs the Raft storage backend and cluster topology across availability zones.",
        note: "No customer action; informational for the shared-responsibility picture." },
      enterprise: { t: "Integrated storage (Raft)", resp: "customer", sev: "medium",
        desc: "Run the Raft integrated-storage backend with a resilient multi-node topology.",
        why: "Raft removes external storage dependencies and gives snapshot-based backup with strong consistency.",
        criteria: [
          "Storage backend is raft (vault status shows Storage Type: raft)",
          "An odd number of voting nodes (3 or 5) is deployed across availability zones",
          "raft list-peers shows all expected voters healthy",
          "The Raft port (8201) is restricted to cluster members only",
        ] },
    } },
  { id: "V-03", d: "vault-platform", sev: "critical", variants: {
      hcp: { t: "Audit log streaming", resp: "shared",
        desc: "Stream Vault audit logs off-cluster to a durable log store or SIEM.",
        why: "Audit logs are the primary record of every secret access; without streaming there is no durable forensic trail.",
        criteria: [
          "Audit log streaming is enabled and active",
          "Logs stream to a SIEM or central store, not only the cluster",
          "Audit delivery failures are alerted on",
        ] },
      enterprise: { t: "Enable audit logging", resp: "customer",
        desc: "Enable at least one (preferably two) audit devices and forward logs to a central store.",
        why: "Audit logs are the primary record of every request; a total audit failure also halts Vault, so device health matters.",
        criteria: [
          "At least one audit device is enabled and active",
          "A second audit device is enabled for redundancy",
          "Logs are rotated and forwarded to a central store or SIEM",
          "Audit device health is monitored (a hung device can stall Vault)",
        ] },
    } },
  { id: "V-04", d: "vault-platform", variants: {
      hcp: { t: "Auto-unseal", resp: "hashicorp",
        desc: "HCP manages seal/unseal with a cloud KMS.",
        note: "Your equivalent custody concern is the admin token (V-05)." },
      enterprise: { t: "Auto-unseal with cloud KMS", resp: "customer", sev: "high",
        desc: "Auto-unseal using a cloud KMS or HSM instead of manual Shamir key entry.",
        why: "Manual unseal is fragile and slows recovery; a KMS seal shifts master-key protection to a managed HSM-backed service.",
        criteria: [
          "Seal type is a cloud KMS or HSM, not shamir",
          "A seal stanza references a dedicated unseal key",
          "The IAM role or identity is scoped to encrypt/decrypt/describe on that key only",
          "Recovery keys (not unseal keys) are generated and distributed",
        ] },
    } },
  { id: "V-05", d: "vault-platform", resp: "customer", sev: "critical", variants: {
      hcp: { t: "Protect the admin token",
        desc: "Avoid routine use of the highly privileged admin token; rotate it and store it securely.",
        why: "The admin token bypasses policy checks; routine use or leakage grants full control of the namespace.",
        criteria: [
          "The admin token is not used for routine operations",
          "Scoped admin policies exist for day-to-day administration",
          "The admin token is rotated on a defined schedule",
          "A documented break-glass process exists for emergency access",
          "The admin token is not stored in automation or source control",
        ] },
      enterprise: { t: "Restrict root token usage",
        desc: "Revoke the initial root token after setup and gate emergency use behind a break-glass procedure.",
        why: "The root token bypasses all policy checks; routine use or leakage grants unrestricted control of the cluster.",
        criteria: [
          "The initial root token has been revoked after setup",
          "Scoped admin policies exist for day-to-day administration",
          "generate-root is used only for genuine emergencies and revoked immediately after",
          "No requests use the root policy outside initial setup (checked in audit logs)",
        ] },
    } },
  // ---- Vault: Auth & Identity (same across deployments) -----------------
  { id: "V-06", d: "vault-auth", t: "OIDC / enterprise SSO auth", resp: "customer", sev: "high",
    desc: "Authenticate people through your identity provider rather than static tokens.",
    why: "Centralises password policy and conditional access, and lets you deprovision access immediately.",
    criteria: [
      "The OIDC (or equivalent SSO) auth method is enabled",
      "IdP groups or claims map to least-privilege roles",
      "No IdP group maps to a broad administrative policy",
      "Redirect URIs and discovery config are correctly scoped",
    ] },
  { id: "V-07", d: "vault-auth", t: "Login MFA", resp: "customer", sev: "high",
    desc: "Require MFA for logins or sensitive operations.",
    why: "A stolen password or token alone should not be enough to reach secrets.",
    criteria: [
      "An MFA method is configured",
      "Login MFA enforcement is bound to auth mounts or groups",
      "MFA is required for privileged and administrative access",
      "A tested MFA reset / break-glass procedure exists",
    ] },
  { id: "V-08", d: "vault-auth", t: "Short token and lease TTLs", resp: "customer", sev: "high",
    desc: "Set conservative default and maximum TTLs so credentials expire and re-validate.",
    why: "Long-lived tokens that leak stay a standing risk indefinitely.",
    criteria: [
      "Auth-method TTLs are tuned rather than left at defaults",
      "Secrets-engine mount TTLs are tuned to policy",
      "System-wide default and max lease TTLs are set as a backstop",
      "Periodic tokens are used only where justified, with Agent renewal",
    ] },
  { id: "V-09", d: "vault-auth", t: "Least-privilege policies", resp: "customer", sev: "critical",
    desc: "Scope ACL policies to specific paths and capabilities; avoid wildcards and sudo.",
    why: "Broad grants such as full capabilities on secret/* are effectively near-root over whole secret trees.",
    criteria: [
      "Policies scope paths to specific mounts or prefixes per team or app",
      "No policy grants broad wildcard capabilities over entire secret trees",
      "The sudo capability is removed from non-administrative policies",
      "Policies are cross-referenced to the roles that attach them",
    ] },
  { id: "V-10", d: "vault-auth", t: "Identity group mapping", resp: "customer", sev: "high",
    desc: "Map IdP groups to Vault groups and attach policies to groups, not individuals.",
    why: "Group-based assignment scales and updates access automatically when membership changes.",
    criteria: [
      "Internal Vault groups exist for access assignment",
      "Policies attach to groups rather than individual entities",
      "External IdP groups are aliased to internal groups",
      "Group membership is periodically audited against the IdP",
    ] },
  // ---- Vault: Secrets Engines -------------------------------------------
  { id: "V-11", d: "vault-secrets", t: "KV version 2", resp: "customer", sev: "medium",
    desc: "Use KV v2 for static secrets: versioning, soft-delete, check-and-set.",
    why: "v2 gives recoverability and safe overwrites that v1's single-version model cannot.",
    criteria: [
      "Static secrets use KV v2 mounts",
      "No KV v1 mounts remain for sensitive secrets",
      "Check-and-set is used to prevent accidental overwrites",
    ] },
  { id: "V-12", d: "vault-secrets", t: "Dynamic secrets", resp: "customer", sev: "high", optional: true,
    desc: "Generate short-lived, on-demand credentials for databases and cloud instead of static ones.",
    why: "Dynamic credentials are unique per lease and auto-revoke, removing standing shared credentials.",
    poc: "Stand up the database secrets engine against one non-prod database, issue a short-TTL role, and demonstrate automatic revocation.",
    criteria: [
      "Dynamic engines are enabled for databases or cloud where applicable",
      "Roles are scoped to least-privilege downstream permissions",
      "Lease TTLs align with the TTL policy (V-08)",
      "Static long-lived credentials have been migrated where feasible",
    ] },
  { id: "V-13", d: "vault-secrets", t: "KV version limits", resp: "customer", sev: "low",
    desc: "Bound retained secret versions with max_versions.",
    why: "Unbounded history keeps old, potentially compromised values recoverable and grows storage.",
    criteria: [
      "max_versions is set to an approved value rather than the default",
      "delete_version_after is configured for highly sensitive mounts",
    ] },
  { id: "V-14", d: "vault-secrets", t: "Path segmentation", resp: "customer", sev: "medium",
    desc: "Namespace paths by environment, team, and application.",
    why: "Clear segmentation is what makes simple least-privilege policies possible.",
    criteria: [
      "A documented path naming convention exists (environment/team/app)",
      "Secret paths follow the convention consistently",
      "Separate mounts are used per environment where isolation is required",
      "Policies align to the path structure, not broad top-level wildcards",
    ] },
  { id: "V-15", d: "vault-secrets", t: "Response wrapping", resp: "customer", sev: "medium", optional: true,
    desc: "Deliver initial secrets through single-use wrap-ttl tokens.",
    why: "Wrapping makes interception of bootstrap secrets detectable and one-time.",
    poc: "Wrap one bootstrap token delivery in CI and show the single-use unwrap plus tamper detection.",
    criteria: [
      "Bootstrap and initial secrets are delivered via wrap-ttl",
      "Provisioning tooling unwraps promptly and never persists the wrapping token",
      "Unwrap operations are reviewed in audit logs",
    ] },
  // ---- Vault: PKI (capability) ------------------------------------------
  { id: "V-16", d: "vault-pki", t: "Short-lived certificates", resp: "customer", sev: "medium",
    desc: "Issue certificates with hours-to-days TTLs on demand.",
    why: "Short lifetimes shrink the window a stolen key is useful and reduce reliance on revocation.",
    criteria: [
      "PKI role TTLs are hours-to-days (commonly 72h or less for workloads)",
      "Issued certificate lifetimes match the role configuration",
      "Automated renewal is in place (Vault Agent, consul-template, or cert-manager)",
    ] },
  { id: "V-17", d: "vault-pki", t: "Intermediate CA hierarchy", resp: "customer", sev: "high",
    desc: "Issue from intermediates signed by a protected root, not directly from the root.",
    why: "A compromised intermediate can be revoked and reissued without collapsing the whole trust chain.",
    criteria: [
      "Leaf certificates are issued from an intermediate, not the root",
      "The root is external or in a separate, more restricted mount or namespace",
      "Clients trust the full chain (root and intermediate)",
    ] },
  { id: "V-18", d: "vault-pki", t: "CRL and OCSP", resp: "customer", sev: "low",
    desc: "Publish revocation status for issued certificates.",
    why: "Revocation lets you invalidate a certificate before its natural expiry after a key compromise.",
    criteria: [
      "CRL generation is enabled with an appropriate expiry",
      "Issuing-certificate and CRL distribution URLs are configured and reachable",
      "The OCSP responder is enabled where supported",
    ] },
  { id: "V-19", d: "vault-pki", t: "Secure the root CA", resp: "customer", sev: "high",
    desc: "Protect the root with minimal use, restricted access, and sealed or offline storage.",
    why: "Root compromise invalidates the entire PKI and forces reissuing every certificate.",
    criteria: [
      "Root CA mount access is restricted to a small, named admin group",
      "The root mount is isolated in a separate namespace or mount",
      "MFA is required for root CA access",
      "The root is sealed, offline, or access-revoked between signings",
      "A documented root signing ceremony exists",
    ] },
  // ---- Vault: Transit (capability) --------------------------------------
  { id: "V-20", d: "vault-transit", t: "Disable key export", resp: "customer", sev: "high",
    desc: "Keep Transit keys non-exportable (the default).",
    why: "Export lets raw key material leave Vault's control, defeating encryption-as-a-service.",
    criteria: [
      "Production Transit keys are non-exportable",
      "No policy grants the export capability on transit/export/*",
      "Any exportable key has a documented, approved need and a tightened policy",
    ] },
  { id: "V-21", d: "vault-transit", t: "Rotate keys", resp: "customer", sev: "medium",
    desc: "Rotate keys on a schedule and phase out old versions with min_decryption_version.",
    why: "Rotation limits data bound to any single key version and its blast radius.",
    criteria: [
      "A rotation schedule or auto_rotate_period is configured",
      "Ciphertext is rewrapped to the latest version periodically",
      "min_decryption_version is advanced only after rewrapping",
    ] },
  { id: "V-22", d: "vault-transit", t: "Derived keys (multi-tenant)", resp: "customer", sev: "low",
    desc: "Use per-context derivation to isolate tenants under one base key.",
    why: "Derived keys cryptographically isolate tenant data without a key per tenant.",
    criteria: [
      "Multi-tenant keys are created with derived=true",
      "A unique, deterministic context is used per tenant",
      "The context is supplied on every encrypt and decrypt call",
    ] },
  { id: "V-23", d: "vault-transit", t: "Scoped Transit access", resp: "customer", sev: "high",
    desc: "Grant encrypt/decrypt only against each service's own named key.",
    why: "Wildcard transit access lets any service operate on other services' keys, breaking isolation.",
    criteria: [
      "Policies reference specific key names, not transit/encrypt/*",
      "There is one Transit key per service or well-defined data domain",
      "The key inventory is mapped to the apps and policies using each key",
    ] },
  // ---- Vault: Kubernetes (capability) -----------------------------------
  { id: "V-24", d: "vault-k8s", t: "Kubernetes auth method", resp: "customer", sev: "high",
    desc: "Let pods authenticate with their projected service-account tokens.",
    why: "Ties Vault access to Kubernetes identity that the platform rotates, removing static tokens.",
    criteria: [
      "The Kubernetes auth method is enabled and points at the correct API server",
      "Roles bind specific service accounts and namespaces, not wildcards",
      "The token-reviewer JWT and CA cert are correctly configured",
    ] },
  { id: "V-25", d: "vault-k8s", t: "RBAC restrictions", resp: "customer", sev: "high",
    desc: "Keep the token-reviewer and injector service accounts minimally privileged.",
    why: "An over-permissioned reviewer service account can grant broad cluster access if compromised.",
    criteria: [
      "The token-reviewer service account is bound only to system:auth-delegator",
      "No Vault-related service account is bound to cluster-admin or broad roles",
      "The Agent Injector uses the official chart's RBAC baseline",
    ] },
  { id: "V-26", d: "vault-k8s", t: "Network policies", resp: "customer", sev: "medium",
    desc: "Restrict which pods and namespaces can reach the Vault service.",
    why: "Without policies any pod can reach Vault, easing lateral movement.",
    criteria: [
      "A default-deny ingress policy exists in the Vault namespace",
      "Ingress is limited to namespaces and pods that legitimately need Vault",
      "The CNI plugin enforces NetworkPolicy",
    ] },
  { id: "V-27", d: "vault-k8s", t: "Pod security standards", resp: "customer", sev: "medium",
    desc: "Apply restricted or baseline Pod Security to Vault-related namespaces.",
    why: "Vault pods hold decrypted secrets in memory; excess privilege worsens a container escape.",
    criteria: [
      "Vault namespaces carry Pod Security Admission labels (restricted or baseline)",
      "Containers run non-root with minimal capabilities",
      "An admission controller enforces the standard where needed",
    ] },
  { id: "V-28", d: "vault-k8s", t: "Secrets injection", resp: "customer", sev: "medium",
    desc: "Inject secrets via the Agent Injector or CSI provider rather than plain K8s Secrets.",
    why: "Native Secrets are base64 by default and often broadly readable via RBAC.",
    criteria: [
      "Secrets are injected via the Agent Injector or CSI provider",
      "Pod annotations reference the correct role and templates",
      "Redundant plain Kubernetes Secret objects have been removed",
      "Any remaining Kubernetes Secrets use KMS encryption at rest",
    ] },
  // ---- Vault: Cloud & Network -------------------------------------------
  { id: "V-29", d: "vault-cloud", variants: {
      hcp: { t: "KMS / Key Vault auto-unseal", resp: "hashicorp",
        desc: "HCP manages auto-unseal against the cloud KMS for the cluster.",
        note: "No customer action; informational." },
      enterprise: { t: "Scope the auto-unseal KMS key", resp: "customer", sev: "high",
        desc: "Use a dedicated KMS or Key Vault key for auto-unseal with a tightly scoped policy and rotation.",
        why: "The unseal key and the identity that can use it are a high-value control point for the whole cluster.",
        criteria: [
          "A dedicated key (CMK or Key Vault key) is used only for Vault auto-unseal",
          "The key policy or RBAC grants only Vault's identity encrypt/decrypt/describe",
          "Key rotation is enabled",
          "Access to the key is logged (CloudTrail or Azure Monitor)",
        ] },
    } },
  { id: "V-30", d: "vault-cloud", t: "Cloud IAM / Managed Identity auth", resp: "customer", sev: "high", optional: true,
    desc: "Let cloud compute authenticate to Vault by its cloud identity, without static tokens.",
    why: "Uses cloud-rotated identity instead of long-lived Vault credentials on workloads.",
    poc: "Enable AWS IAM (or Azure MI) auth for one workload role and remove its static Vault token.",
    criteria: [
      "AWS IAM (or Azure Managed Identity) auth is enabled",
      "Roles bind specific principals, not account-wide wildcards",
      "Workloads no longer carry static Vault tokens",
    ] },
  { id: "V-31", d: "vault-cloud", sev: "high", variants: {
      hcp: { t: "Private connectivity", resp: "shared",
        desc: "Reach the cluster over HVN peering, PrivateLink, or transit gateway rather than the public endpoint.",
        why: "Private connectivity keeps Vault traffic off the public internet.",
        criteria: [
          "The cluster is reached via peering, PrivateLink, or transit gateway",
          "Public access to the cluster is restricted or disabled",
          "Client networks route to Vault privately",
        ] },
      enterprise: { t: "Private connectivity", resp: "customer",
        desc: "Place Vault in private networks and reach its cloud dependencies over private endpoints.",
        why: "Private connectivity keeps the Vault API and its dependency traffic off the public internet.",
        criteria: [
          "Vault nodes sit in private subnets or a dedicated VNet with no public exposure",
          "KMS and snapshot-storage traffic uses VPC endpoints or Private Link",
          "Client networks reach Vault over private routes",
        ] },
    } },
  { id: "V-32", d: "vault-cloud", variants: {
      hcp: { t: "Client network controls", resp: "shared", sev: "medium",
        desc: "Restrict which client subnets and security groups can reach Vault.",
        why: "Overly open ingress increases exposure to scanning and exploitation.",
        criteria: [
          "Ingress to Vault is scoped to known client sources",
          "No rule allows 0.0.0.0/0 or Any to the Vault ports",
          "Client-side security groups or NSGs are least-privilege",
        ] },
      enterprise: { t: "Security groups / NSGs on Vault nodes", resp: "customer", sev: "high",
        desc: "Restrict ingress to the Vault API (8200) and cluster (8201) ports to known clients and peers.",
        why: "Open ingress exposes the Vault API to scanning and the cluster port to tampering.",
        criteria: [
          "No rule allows 0.0.0.0/0 or Any to 8200 or 8201",
          "8200 ingress is scoped to the load balancer or known client sources",
          "8201 ingress is restricted to Vault cluster nodes only",
        ] },
    } },
  { id: "V-33", d: "vault-cloud", t: "IMDSv2 on client instances", resp: "customer", sev: "medium", cloud: "aws",
    desc: "Enforce IMDSv2 on EC2 clients that use the AWS auth method.",
    why: "IMDSv1 is exposed to SSRF-based theft of instance IAM credentials.",
    criteria: [
      "EC2 clients enforce IMDSv2 (HttpTokens set to required)",
      "Launch templates and Auto Scaling Groups set IMDSv2 for new instances",
      "Legacy IMDSv1-only tooling has been updated",
    ] },
  { id: "V-34", d: "vault-cloud", t: "Entra ID (Azure AD) integration", resp: "customer", sev: "medium", cloud: "azure", optional: true,
    desc: "Federate Entra ID for human login or use the Azure secrets engine for short-lived SP credentials.",
    why: "Aligns Vault access and Azure resource access to one identity lifecycle.",
    poc: "Federate Entra ID via OIDC for one login role, or enable the Azure secrets engine for short-lived SP credentials.",
    criteria: [
      "Entra ID is federated via OIDC for login, or the Azure secrets engine is in use",
      "The Vault app registration holds only the minimum required permissions with admin consent",
      "The discovery URL points at the correct tenant",
    ] },
  // ---- Vault: Monitoring ------------------------------------------------
  { id: "V-39", d: "vault-mon", sev: "medium", variants: {
      hcp: { t: "Metrics streaming", resp: "shared",
        desc: "Stream Vault operational metrics to your monitoring stack.",
        why: "Metrics catch seal failures, storage latency, and lease churn before they become outages.",
        criteria: [
          "Metrics streaming or telemetry is enabled",
          "Metrics reach the monitoring stack (Prometheus, Datadog, or similar)",
          "The metrics endpoint is access-controlled or network-restricted",
        ] },
      enterprise: { t: "Enable telemetry", resp: "customer",
        desc: "Expose Vault telemetry to your monitoring stack via a telemetry stanza.",
        why: "Metrics catch seal failures, storage latency, and lease churn before they become outages.",
        criteria: [
          "A telemetry stanza is configured",
          "Metrics reach the monitoring stack (Prometheus, Datadog, or similar)",
          "The metrics endpoint is access-controlled or network-restricted",
        ] },
    } },
  { id: "V-40", d: "vault-mon", sev: "medium", variants: {
      hcp: { t: "Central logging & retention", resp: "shared",
        desc: "Centralise audit and operational logs with compliance-aligned retention.",
        why: "Central logs survive host compromise and enable cross-system correlation.",
        criteria: [
          "Server and audit logs ship to a central store",
          "Retention meets compliance requirements",
          "Log-volume alerting detects shipping-pipeline failures",
        ] },
      enterprise: { t: "Central logging & retention", resp: "customer",
        desc: "Ship Vault server and audit logs off the host with compliance-aligned retention.",
        why: "Central logs survive host compromise and enable cross-system correlation.",
        criteria: [
          "Server and audit logs ship to a central store",
          "Retention meets compliance requirements",
          "Log-volume alerting detects shipping-pipeline failures",
        ] },
    } },
  { id: "V-41", d: "vault-mon", t: "SIEM integration", resp: "customer", sev: "high",
    desc: "Parse Vault audit events in the SIEM with detection rules.",
    why: "Raw audit logs only help if something is actively watching them.",
    criteria: [
      "Vault audit events are parsed correctly in the SIEM",
      "Detection rules exist for root/admin-token use, policy changes, and mass reads",
      "Log-delivery latency meets the detection SLA",
    ] },
  { id: "V-42", d: "vault-mon", t: "Alerting rules", resp: "customer", sev: "high",
    desc: "Alert on seal status, failover, certificate expiry, and audit-write failures.",
    why: "Without alerts, a sealed cluster or failing audit device goes unnoticed until users report an outage.",
    criteria: [
      "Alerts cover seal status, failover, and Raft/quorum health",
      "Alerts cover audit-device write failures",
      "Alerts cover TLS and PKI certificate expiry",
      "Security-relevant alerts route to the security team",
    ] },
  // ---- Vault: Disaster Recovery -----------------------------------------
  { id: "V-43", d: "vault-dr", variants: {
      hcp: { t: "Backup encryption & access", resp: "shared", sev: "low",
        desc: "HCP runs platform backups; any snapshots you take yourself must be encrypted and access-controlled.",
        why: "A snapshot is a portable copy of the entire dataset.",
        criteria: [
          "Self-managed snapshot storage enforces encryption at rest",
          "Access to snapshot storage is restricted to a dedicated backup role",
          "The unseal-key dependency for restore is documented",
        ] },
      enterprise: { t: "Encrypted snapshots", resp: "customer", sev: "medium",
        desc: "Take Raft snapshots and protect them with encryption at rest and restricted access.",
        why: "A snapshot is a portable, complete copy of the Vault dataset.",
        criteria: [
          "Raft snapshots are taken on a schedule",
          "Snapshot storage enforces encryption at rest",
          "Access is restricted to a dedicated backup role",
          "The unseal-key dependency for restore is documented",
        ] },
    } },
  { id: "V-44", d: "vault-dr", variants: {
      hcp: { t: "Snapshot protection", resp: "shared", sev: "low", optional: true,
        desc: "Apply immutability and versioning to any self-managed snapshots.",
        why: "Immutability defends snapshots against tampering or deletion ahead of a destructive attack.",
        poc: "For one self-managed snapshot bucket, enable versioning and Object Lock, then confirm delete is blocked.",
        criteria: [
          "Snapshot storage has versioning or immutability enabled",
          "Delete permissions on snapshots are tightly restricted",
          "Access logging is enabled on snapshot storage",
        ] },
      enterprise: { t: "Snapshot protection", resp: "customer", sev: "medium",
        desc: "Apply immutability and versioning to snapshots and restrict who can delete them.",
        why: "Immutability defends snapshots against tampering or deletion before a destructive attack.",
        criteria: [
          "Snapshot storage has versioning or immutability (Object Lock / immutable blob)",
          "Delete permissions on snapshots are tightly restricted",
          "Access logging is enabled on snapshot storage",
        ] },
    } },
  { id: "V-45", d: "vault-dr", sev: "medium", variants: {
      hcp: { t: "Restore & recovery validation", resp: "shared",
        desc: "Validate that applications and auth work after a restore or DR event.",
        why: "HashiCorp operates managed backups, but application recovery still needs your validation.",
        criteria: [
          "A recovery or restore validation was performed in the last 6-12 months",
          "Validation includes auth and an application-level smoke test",
          "The restore procedure is documented and current",
          "Cross-region DR is enabled where the RTO requires it",
        ] },
      enterprise: { t: "Restore testing", resp: "customer",
        desc: "Periodically restore a snapshot into a non-prod environment and validate unseal and apps.",
        why: "Untested backups are not a reliable DR control; problems surface only during a real incident.",
        criteria: [
          "A full restore test was performed in the last 6-12 months",
          "The test validated auto-unseal (or documented Shamir unseal)",
          "The test included an application-level smoke test",
          "The restore procedure is documented and current",
        ] },
    } },
  { id: "V-46", d: "vault-dr", variants: {
      hcp: { t: "Seal / recovery key custody", resp: "hashicorp",
        desc: "HCP manages seal/unseal and recovery key custody for the platform.",
        note: "Your equivalent custody concern is the admin token (V-05)." },
      enterprise: { t: "Unseal & recovery key security", resp: "customer", sev: "high",
        desc: "Distribute unseal or recovery key shares across separate custodians and locations so no one holds a quorum.",
        why: "Key shares held by one person or in one place defeat key splitting and put the master key at risk.",
        criteria: [
          "Shares are split with a quorum (for example 3 of 5) across distinct custodians",
          "Shares are stored in separate secure locations",
          "Custodians are current staff with documented succession",
          "Rekey is run when custodians change",
        ] },
    } },
  // ---- Vault: Enterprise Platform (Enterprise self-managed only) --------
  { id: "V-47", d: "vault-ent", appliesTo: ["enterprise"], t: "Replication (performance & DR)", resp: "customer", sev: "high",
    desc: "Use performance and disaster-recovery replication for scale and failover, and test promotion.",
    why: "Replication provides scale and a warm standby; an untested DR secondary is not a recovery plan.",
    criteria: [
      "DR replication to a secondary cluster is configured",
      "Performance replication is used where scale or locality requires it",
      "Replication status and lag are monitored",
      "DR promotion has been tested",
    ] },
  { id: "V-48", d: "vault-ent", appliesTo: ["enterprise"], t: "Namespaces & tenant isolation", resp: "customer", sev: "medium",
    desc: "Isolate teams or tenants into namespaces with delegated, scoped administration.",
    why: "Namespaces give hard multi-tenancy boundaries and let you delegate admin without cluster-wide power.",
    criteria: [
      "Teams or tenants are separated into namespaces",
      "Administration is delegated per namespace",
      "Policies are scoped within their namespace",
      "No broad cross-namespace grants exist",
    ] },
  { id: "V-49", d: "vault-ent", appliesTo: ["enterprise"], t: "Seal wrap / HSM", resp: "customer", sev: "medium", optional: true,
    desc: "Where compliance requires it, use Seal Wrap and an HSM or FIPS-validated KMS for the seal.",
    why: "Seal Wrap and HSM-backed seals meet FIPS 140 requirements and add defense for critical key material.",
    poc: "Enable Seal Wrap against an HSM or FIPS-validated KMS in a non-prod cluster and confirm the FIPS posture.",
    criteria: [
      "Seal Wrap is enabled where FIPS compliance requires it",
      "The seal uses an HSM (PKCS#11) or FIPS-validated KMS",
      "The FIPS 140 posture is documented for attestations",
    ] },
  { id: "V-50", d: "vault-ent", appliesTo: ["enterprise"], t: "Control groups (dual authorization)", resp: "customer", sev: "medium", optional: true,
    desc: "Require multiple approvers before access to the most sensitive paths.",
    why: "Dual authorization stops a single compromised identity from unilaterally reading critical secrets.",
    poc: "Add a control group requiring a second approver on one highly sensitive path.",
    criteria: [
      "Control groups gate access to sensitive paths",
      "Approver groups are defined and least-privilege",
      "Control-group requirements are reviewed periodically",
    ] },
  { id: "V-51", d: "vault-ent", appliesTo: ["enterprise"], t: "Sentinel policies (EGP/RGP)", resp: "customer", sev: "medium", optional: true,
    desc: "Use endpoint- and role-governing policies for guardrails beyond ACLs.",
    why: "Sentinel enforces conditions such as source CIDR, MFA, or time that ACL policies alone cannot express.",
    poc: "Add one EGP that enforces MFA or a source-CIDR restriction on a sensitive endpoint.",
    criteria: [
      "EGP or RGP policies enforce guardrails on sensitive endpoints",
      "Policies are version-controlled",
      "Enforcement levels (advisory/soft/hard) are set deliberately",
    ] },
  // ---- Terraform: Access & Governance -----------------------------------
  { id: "T-01", d: "tf-access", t: "Enforce SSO", resp: "customer", sev: "critical",
    desc: "Require organisation-wide SAML/OIDC SSO and disable password-only access.",
    why: "SSO centralises identity and enables instant deprovisioning across the org.",
    criteria: [
      "Organisation-wide SAML or OIDC SSO is enabled",
      "SSO is enforced and password-only access is disabled",
      "Access deprovisions through the IdP on offboarding",
    ] },
  { id: "T-02", d: "tf-access", t: "Team RBAC least privilege", resp: "customer", sev: "high",
    desc: "Scope teams to projects and workspaces; minimise org owners; separate plan from apply.",
    why: "Broad org access gives an uncontrolled blast radius over all infrastructure.",
    criteria: [
      "Teams are scoped to specific projects or workspaces",
      "Organisation owners are limited to a minimal set",
      "Plan and apply permissions are separated appropriately",
      "Permissions are reviewed periodically",
    ] },
  { id: "T-03", d: "tf-access", resp: "customer", sev: "high", variants: {
      hcp: { t: "Audit log streaming",
        desc: "Stream HCP Terraform audit logs to your SIEM.",
        why: "Audit trails let you detect suspicious admin and configuration activity.",
        criteria: [
          "Audit logs stream to a SIEM",
          "Membership, permission, and policy-change events are parsed",
          "Delivery is monitored",
        ] },
      enterprise: { t: "Audit trail forwarding",
        desc: "Forward TFE audit logs off the platform to your SIEM.",
        why: "Audit trails let you detect suspicious admin and configuration activity.",
        criteria: [
          "TFE audit logs are forwarded off-box to a SIEM",
          "Membership, permission, and policy-change events are parsed",
          "Log forwarding is monitored for gaps",
        ] },
    } },
  // ---- Terraform: Credentials & State -----------------------------------
  { id: "T-04", d: "tf-cred", t: "Dynamic provider credentials", resp: "customer", sev: "critical",
    desc: "Use OIDC/workload-identity to the cloud (or Vault-backed credentials) instead of static keys in variables.",
    why: "Removes long-lived cloud keys from Terraform and exchanges credentials just-in-time.",
    criteria: [
      "Cloud providers use OIDC / dynamic credentials (or Vault-backed)",
      "No static cloud keys are stored in workspace variables",
      "Credential scope is least-privilege per workspace or project",
    ] },
  { id: "T-05", d: "tf-cred", t: "Sensitive variables, no hardcoded secrets", resp: "customer", sev: "critical",
    desc: "Mark variables sensitive, prefer ephemeral/write-only values, and never commit secrets.",
    why: "Plaintext secrets in configuration or state leak widely and persist in history.",
    criteria: [
      "Secrets are marked sensitive (or use write-only / ephemeral values)",
      "No secrets are hardcoded in configuration or committed to VCS",
      "Secret-manager references are used where possible",
    ] },
  { id: "T-06", d: "tf-cred", t: "State access control", resp: "customer", sev: "high",
    desc: "Only Terraform and CI should read or write state; avoid local state for production.",
    why: "State holds sensitive resource data and outputs.",
    criteria: [
      "State lives in Terraform (HCP or TFE), not local for production",
      "State access is restricted via team permissions",
      "Local applies are disabled for production workspaces",
    ] },
  // ---- Terraform: Workflow & Change Control -----------------------------
  { id: "T-07", d: "tf-flow", t: "VCS-driven workflow", resp: "customer", sev: "high",
    desc: "Drive production changes through VCS with review; use private VCS access; no CLI applies to prod.",
    why: "A VCS-driven flow enforces review and traceability for every change.",
    criteria: [
      "Production workspaces are VCS-connected",
      "The main branch is protected with required review",
      "CLI and local applies to production are disabled",
      "VCS connectivity is private or secured",
    ] },
  { id: "T-08", d: "tf-flow", t: "Apply approvals & run governance", resp: "customer", sev: "medium",
    desc: "Require confirmed applies and restrict who can apply.",
    why: "Gating apply prevents unreviewed changes reaching production.",
    criteria: [
      "Manual apply confirmation is required on production",
      "Apply permission is limited to specific teams",
      "Auto-apply is disabled where review is required",
    ] },
  { id: "T-09", d: "tf-flow", t: "Drift detection / health assessments", resp: "customer", sev: "medium", optional: true,
    desc: "Enable health assessments and drift detection on critical workspaces.",
    why: "Drift detection surfaces out-of-band changes before they cause an incident.",
    poc: "Enable health assessments for one production workspace and review the first drift report.",
    criteria: [
      "Health assessments / drift detection are enabled on critical workspaces",
      "Drift reports are reviewed on a schedule",
    ] },
  // ---- Terraform: Policy as Code ----------------------------------------
  { id: "T-10", d: "tf-policy", t: "Policy as code (Sentinel/OPA)", resp: "customer", sev: "high",
    desc: "Enforce policy sets on runs to validate plans against security and cost rules.",
    why: "Codified guardrails catch insecure plans before apply, not just in code review.",
    criteria: [
      "Sentinel or OPA policy sets are attached to workspaces or projects",
      "Non-negotiable policies are hard-enforced",
      "Coverage includes encryption, tagging, and region or size guardrails",
    ] },
  { id: "T-11", d: "tf-policy", t: "Run tasks for pre-apply checks", resp: "customer", sev: "medium", optional: true,
    desc: "Integrate security-scanning run tasks into the run lifecycle.",
    why: "Run tasks shift security checks left into the plan/apply flow.",
    poc: "Wire one IaC-scanning run task to a non-prod workspace as advisory, then promote it to mandatory.",
    criteria: [
      "A security-scanning run task is integrated at pre-plan or pre-apply",
      "Run-task vendors are vetted, since they receive plan data",
      "Critical findings block the run where appropriate",
    ] },
  // ---- Terraform: Modules & Supply Chain --------------------------------
  { id: "T-12", d: "tf-mods", t: "Private module registry & versioning", resp: "customer", sev: "medium",
    desc: "Publish curated modules to a private registry with pinned versions.",
    why: "A curated registry gives consistent, reviewed building blocks.",
    criteria: [
      "Approved modules are published to a private registry",
      "Module versions are pinned",
      "No-code or curated modules are offered for self-service",
    ] },
  { id: "T-13", d: "tf-mods", t: "Provider & module verification", resp: "customer", sev: "medium",
    desc: "Verify the source and integrity of providers and modules; restrict to approved sources.",
    why: "Providers and modules are external code and carry supply-chain risk.",
    criteria: [
      "Providers and modules are pinned and version-locked",
      "Sources are restricted to an approved registry",
      "Integrity or signatures are verified where available",
    ] },
  // ---- Terraform: Connectivity & Agents ---------------------------------
  { id: "T-14", d: "tf-agents", t: "Self-hosted agents scoped", resp: "customer", sev: "medium", optional: true,
    desc: "If using agents for private infrastructure, scope, patch, and network-isolate them.",
    why: "An over-privileged agent bridges the control plane into your private networks.",
    poc: "Deploy one agent pool for a single private workspace with minimal egress and a rotated token.",
    criteria: [
      "Agents run least-privilege and network-segmented",
      "Agents are patched and updated regularly",
      "Agent tokens are rotated",
    ] },
  // ---- Terraform: Self-Hosted Operations (Enterprise self-hosted only) --
  { id: "T-15", d: "tf-ops", appliesTo: ["enterprise"], t: "Platform & host hardening", resp: "customer", sev: "medium",
    desc: "Run TFE on a supported install and version, on a hardened, patched host.",
    why: "The TFE host and platform now sit inside your trust boundary and carry the usual server-hardening obligations.",
    criteria: [
      "TFE runs on a supported install method and version",
      "The host OS is patched and hardened",
      "Host and container access is restricted to operators",
      "Only required services and ports run on the host",
    ] },
  { id: "T-16", d: "tf-ops", appliesTo: ["enterprise"], t: "TLS on TFE", resp: "customer", sev: "high",
    desc: "Serve TFE over TLS with a valid certificate and a rotation process.",
    why: "TFE handles credentials, state, and run data; plaintext transport exposes all of it.",
    criteria: [
      "TFE serves over TLS with a valid certificate",
      "TLS is minimum version 1.2 with weak ciphers disabled",
      "If a load balancer terminates TLS, traffic to TFE is re-encrypted or kept private",
      "A certificate rotation process exists",
    ] },
  { id: "T-17", d: "tf-ops", appliesTo: ["enterprise"], t: "External PostgreSQL security", resp: "customer", sev: "high",
    desc: "Use an external, managed PostgreSQL with TLS, least-privilege credentials, and encrypted backups.",
    why: "The external database holds TFE's application data; its security and durability are yours to own.",
    criteria: [
      "TFE uses an external managed PostgreSQL for production (not internal mode)",
      "Connections to PostgreSQL use TLS",
      "The database credential is least-privilege",
      "The database is backed up and encrypted at rest",
    ] },
  { id: "T-18", d: "tf-ops", appliesTo: ["enterprise"], t: "Object storage security", resp: "customer", sev: "high",
    desc: "Use external object storage with encryption at rest, scoped access, and versioning.",
    why: "Object storage holds state and artifacts; exposure or loss there is a direct breach or outage.",
    criteria: [
      "TFE uses external object storage (S3/Azure Blob/GCS) for production",
      "Object storage enforces encryption at rest",
      "Access is scoped to TFE's identity and not public",
      "Versioning is enabled",
    ] },
  { id: "T-19", d: "tf-ops", appliesTo: ["enterprise"], t: "TFE backups & DR", resp: "customer", sev: "high",
    desc: "Run automated, encrypted TFE backups and test restores against a documented RTO/RPO.",
    why: "Self-hosting makes TFE recovery your responsibility, not HashiCorp's.",
    criteria: [
      "Automated TFE backups run on a schedule (backup API or snapshot)",
      "Backups are encrypted and access-controlled",
      "A restore has been tested",
      "RTO and RPO are documented",
    ] },
  { id: "T-20", d: "tf-ops", appliesTo: ["enterprise"], t: "Encryption password & internal Vault", resp: "customer", sev: "critical",
    desc: "Store and back up the TFE encryption password securely, and understand the internal-Vault unseal path.",
    why: "The encryption password unseals TFE's internal Vault; losing it can render backups and state unrecoverable.",
    criteria: [
      "The TFE encryption password is stored securely and backed up",
      "It is kept out of source control and CI logs",
      "The internal-Vault unseal/rekey behaviour is understood",
      "A recovery plan exists for a lost encryption password",
    ] },
  { id: "T-21", d: "tf-ops", appliesTo: ["enterprise"], t: "Upgrades & patching", resp: "customer", sev: "medium",
    desc: "Keep TFE on a supported release with a defined upgrade cadence and staged validation.",
    why: "Self-hosted TFE only receives fixes when you upgrade it.",
    criteria: [
      "TFE runs a currently supported release",
      "An upgrade cadence is defined",
      "Security advisories and release notes are tracked",
      "Upgrades are validated in staging before production",
    ] },
  { id: "T-22", d: "tf-ops", appliesTo: ["enterprise"], t: "Admin console & network exposure", resp: "customer", sev: "high",
    desc: "Restrict admin/console access and avoid exposing TFE to the public internet.",
    why: "An exposed admin surface is a direct path to full control of your Terraform runs and state.",
    criteria: [
      "Admin/console access is restricted to administrators and known networks",
      "TFE is not exposed to the public internet unless explicitly required",
      "The deployment is network-segmented from general workloads",
      "Administrators authenticate with SSO and MFA",
    ] },
];

/* ---- deployment resolution -------------------------------------------- */
function resolve(c, meta) {
  const product = DOMAIN_PRODUCT[c.d];
  const dep = activeDeploy(product, meta);
  const v = c.variants && c.variants[dep];
  const merged = v ? { ...c, ...v } : { ...c };
  merged.product = product;
  merged.stage = STAGE_TAGS[c.id] || null;
  delete merged.variants;
  return merged;
}
function controlApplies(c, meta) {
  const product = DOMAIN_PRODUCT[c.d];
  const dep = activeDeploy(product, meta);
  if (c.appliesTo && !c.appliesTo.includes(dep)) return false;
  const rc = resolve(c, meta);
  if (rc.cloud && rc.cloud !== meta.cloud) return false;
  return true;
}
function domainApplies(dom, meta) {
  const dep = activeDeploy(dom.product, meta);
  if (dom.appliesTo && !dom.appliesTo.includes(dep)) return false;
  return CONTROLS.some((c) => c.d === dom.id && controlApplies(c, meta));
}

/* System-derived alignment from ticked criteria. */
function alignmentFor(rc, a) {
  const total = rc.criteria ? rc.criteria.length : 0;
  if (!total) return null;
  const checks = a.checks || {};
  const done = rc.criteria.reduce((n, _, i) => n + (checks[i] ? 1 : 0), 0);
  const r = done / total;
  let level;
  if (r >= 1) level = "full";
  else if (r < ONE_THIRD) level = "none";
  else level = "partial";
  return { level, done, total, r };
}

/* A control is "met" for the maturity gate only when fully aligned
   (or, for a control with no criteria, when marked in use). */
function isMet(rc, a) {
  if ((a.status || "unset") !== "implemented") return false;
  const al = alignmentFor(rc, a);
  return al ? al.level === "full" : true;
}

/* ---- inlined official HashiCorp / Vault / Terraform marks ------------- *
 * HashiCorp corporate mark inherits currentColor (safe to recolour).
 * The Vault and Terraform lockups are the dark-background variants
 * (white wordmark), so they are only placed on dark bands, unmodified.  */
function HashiMark({ size = 26, color = "currentColor", title = "HashiCorp" }) {
  return (
    <svg width={size} height={size} viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg"
      role="img" aria-label={title} style={{ display: "block" }}>
      <path fill={color} d="M372.1 43.9V329l-75.8 43.6v-82.4h-80.5V512l-75.5-43.9V183l75.5-43.6v83h80.5V0zm125.6 72.7v279.2L296.3 512v-87.4l126-72.7V72.7zm-282-29.2L90.1 160.1v279.2l-75.8-43.9V116.3L215.7 0z" />
    </svg>
  );
}
function VaultLockup({ height = 22 }) {
  const w = height * (163.61 / 72);
  return (
    <svg height={height} width={w} viewBox="16.55 0 163.61 72" xmlns="http://www.w3.org/2000/svg"
      role="img" aria-label="Vault" style={{ display: "block" }}>
      <path fill="#ffcf25" d="m16.55 10.39 26.46 51.5 26.65-51.5zm22.34 20.44h-4.22v-4.21h4.22zm0-6.32h-4.22v-4.22h4.22zm6.32 12.65h-4.22v-4.22h4.22zm0-6.32h-4.22v-4.21h4.22zm0-6.32h-4.22V20.3h4.22zm6.29 6.32h-4.22v-4.21h4.22zm-4.22-6.32V20.3h4.22v4.22z" />
      <path fill="#fff" d="m94.16 50.99-8.2-28h5.4l6.5 23.4h1.4l6.6-23.4h5.1l-8.2 28zm23.5.3c-4.1 0-6.7-2.2-6.7-5.8 0-4.2 3-5.6 6.6-6.4l6.1-1.4v-.4c0-2.1-1.4-3.4-3.5-3.4s-3.5 1.2-3.9 3.1l-4.4-.5c.7-3.8 3.9-6.2 8.5-6.2 5 0 8.3 3.2 8.3 7.8v8.4c0 .5.1.7.5.7h1.1v3.9h-3c-1.9 0-2.8-.6-2.8-2.2q0-.75.3-1.8l-.4-.2c-1.5 3-3.7 4.4-6.7 4.4m-1.8-6.2c0 1.6 1.2 2.6 3 2.6 2.8 0 4.7-2 4.7-5.2v-1.6l-4.5 1.1c-2.2.6-3.2 1.3-3.2 3.1m30.9-3.3v-11.2h5v20.4h-4.9v-.8c0-1 .1-1.8.3-3.2l-.4-.2c-1.2 3-3.2 4.7-6.6 4.7-4.4 0-6.8-2.8-6.8-7.5v-13.4h5v12.8c0 2.7 1.2 4 3.7 4 2.7.1 4.7-2 4.7-5.6m15.7-19.6v23.9c0 .8.3 1 .8 1h2.4v3.9h-4.7c-2.4 0-3.6-1.3-3.6-3.7v-21.1h-3v-4zm13.3 28.8c-3.9 0-5.6-1.6-5.6-5.1v-11.3h-3.6v-4h3.6v-5.2h5v5.2h5v4h-5v10.6c0 1.3.5 1.8 1.5 1.8h3.5v4z" />
    </svg>
  );
}
function TerraformLockup({ height = 22 }) {
  const w = height * (243.89 / 72);
  return (
    <svg height={height} width={w} viewBox="16.06 0 243.89 72" xmlns="http://www.w3.org/2000/svg"
      role="img" aria-label="Terraform" style={{ display: "block" }}>
      <path fillRule="evenodd" fill="#a067da" d="m33.26 17.5 15.5 9v18l-15.5-9zM50.56 26.5v18l15.5-9v-18zM16.06 7.5v18l15.5 9v-18zM33.26 55.5l15.5 9v-18l-15.5-9z" />
      <path fill="#fff" d="M92.86 27.28h-8.99v-4.37h23.16v4.37h-8.95V51h-5.22zM105.42 40.8c0-6.38 4.25-10.67 9.95-10.67s9.95 4.05 9.95 10.23v1.85h-14.97c.28 3.17 2.13 5.38 5.22 5.38 2.37 0 3.69-1.08 4.49-3.05l4.61.72c-1.12 3.77-4.01 6.18-9.11 6.18-5.94 0-10.15-4.41-10.15-10.63Zm5.02-2.05h9.87c-.36-3.01-2.17-4.78-4.94-4.78-2.61 0-4.49 1.85-4.94 4.78ZM128.85 30.57h4.66v.84c0 1.12-.04 2.01-.36 3.61l.48.12c.76-2.69 2.17-4.57 5.46-4.57h1.48v4.9h-2.05c-3.01 0-4.65 1.85-4.65 5.22V51h-5.02zM143.14 30.57h4.66v.84c0 1.12-.04 2.01-.36 3.61l.48.12c.76-2.69 2.17-4.57 5.46-4.57h1.48v4.9h-2.05c-3.01 0-4.66 1.85-4.66 5.22V51h-5.02V30.57ZM155.54 45.54c0-4.21 3.01-5.58 6.58-6.42l6.18-1.44v-.44c0-2.13-1.4-3.45-3.57-3.45s-3.45 1.2-3.89 3.13l-4.41-.52c.68-3.81 3.89-6.26 8.51-6.26 5.06 0 8.35 3.17 8.35 7.83v8.39c0 .52.16.72.52.72h1.12v3.93h-3.01c-1.97 0-2.81-.6-2.81-2.25 0-.48.08-1.08.28-1.81l-.44-.12c-1.44 3.09-3.57 4.49-6.66 4.49-4.05 0-6.74-2.25-6.74-5.78Zm8.07 2.13c2.77 0 4.7-2.01 4.7-5.18v-1.56l-4.53 1.08c-2.25.52-3.21 1.28-3.21 3.05 0 1.61 1.2 2.61 3.05 2.61ZM179.97 34.58h-3.69v-4.01h3.69V27.4c0-3.69 1.73-5.3 5.74-5.3h4.53v3.97h-3.65c-1.2 0-1.69.56-1.69 1.89v2.61h4.78v4.01h-4.7v16.41h-5.02V34.58ZM190.97 40.8c0-6.22 4.29-10.67 10.35-10.67s10.39 4.45 10.39 10.67-4.37 10.63-10.39 10.63-10.35-4.41-10.35-10.63m15.73 0c0-3.93-2.13-6.58-5.38-6.58s-5.38 2.65-5.38 6.58 2.17 6.58 5.38 6.58 5.38-2.65 5.38-6.58M215.13 30.57h4.66v.84c0 1.12-.04 2.01-.36 3.61l.48.12c.76-2.69 2.17-4.57 5.46-4.57h1.48v4.9h-2.05c-3.01 0-4.66 1.85-4.66 5.22V51h-5.02V30.57ZM229.41 30.57h4.9v.88c0 1.08-.08 1.81-.36 3.25l.48.12c1.04-3.17 3.09-4.69 6.3-4.69s5.38 1.48 6.14 4.61h.44c1.08-3.09 3.13-4.61 6.18-4.61 4.21 0 6.46 2.73 6.46 7.42v13.44h-4.74V37.71c0-2.33-1.16-3.61-3.25-3.61-2.73 0-4.65 2.29-4.65 5.66V51h-5.02V37.72c0-2.33-1.12-3.61-3.21-3.61-2.69 0-4.65 2.29-4.65 5.66v11.24h-5.02V30.58Z" />
    </svg>
  );
}

function Badge({ fg, bg, children, mono }) {
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 6, color: fg,
      background: bg, borderRadius: 6, padding: "2px 8px", fontSize: 11.5,
      fontWeight: 650, letterSpacing: 0.2, whiteSpace: "nowrap",
      fontFamily: mono ? "var(--mono)" : "inherit",
    }}>{children}</span>
  );
}

function Seg({ options, value, onChange, size = "md" }) {
  return (
    <div style={{ display: "inline-flex", background: "#EEF0F3", border: `1px solid ${C.line}`,
      borderRadius: 8, padding: 2, gap: 2 }}>
      {options.map((o) => {
        const active = value === o.v;
        return (
          <button key={o.v} onClick={() => onChange(active ? "unset" : o.v)}
            style={{
              cursor: "pointer", border: "none", borderRadius: 6,
              padding: size === "sm" ? "5px 10px" : "7px 13px",
              fontSize: 12.5, fontWeight: 600, letterSpacing: 0.1,
              background: active ? (o.bg || C.panel) : "transparent",
              color: active ? (o.fg || C.ink) : C.muted,
              boxShadow: active ? "0 1px 2px rgba(20,25,40,.12)" : "none",
              transition: "all .12s ease",
            }}>{o.label}</button>
        );
      })}
    </div>
  );
}

export default function App() {
  const [meta, setMeta] = useState({
    customer: "", assessor: "", date: today(), cloud: "aws",
    vaultDeployment: "hcp", tfDeployment: "hcp",
  });
  const [assess, setAssess] = useState({});   // controlId -> {status, checks:{i:true}, notes}
  const [caps, setCaps] = useState({});        // capability domainId -> "assess" | "not_implemented"
  const [activeDomain, setActiveDomain] = useState("vault-platform");
  const [view, setView] = useState("assess");
  const fileRef = useRef(null);

  const visibleDomains = useMemo(
    () => DOMAINS.filter((d) => domainApplies(d, meta)),
    [meta]
  );

  // Keep the active domain valid when a deployment change hides it.
  useEffect(() => {
    if (!visibleDomains.some((d) => d.id === activeDomain) && visibleDomains.length) {
      setActiveDomain(visibleDomains[0].id);
    }
  }, [visibleDomains, activeDomain]);

  const visibleControls = (domainId) =>
    CONTROLS.filter((c) => c.d === domainId && controlApplies(c, meta)).map((c) => resolve(c, meta));

  const setCtl = (id, patch) =>
    setAssess((a) => ({ ...a, [id]: { ...(a[id] || {}), ...patch } }));

  const toggleCheck = (id, i) =>
    setAssess((a) => {
      const cur = a[id] || {};
      const checks = { ...(cur.checks || {}) };
      if (checks[i]) delete checks[i]; else checks[i] = true;
      return { ...a, [id]: { ...cur, checks } };
    });

  const setAllChecks = (rc, on) =>
    setCtl(rc.id, { checks: on ? Object.fromEntries(rc.criteria.map((_, i) => [i, true])) : {} });

  const derived = useMemo(() => {
    const assessable = [];
    for (const dom of DOMAINS) {
      if (!domainApplies(dom, meta)) continue;
      if (dom.capability && caps[dom.id] === "not_implemented") continue;
      for (const rc of visibleControls(dom.id)) {
        if (rc.resp === "hashicorp") continue;
        assessable.push(rc);
      }
    }
    let num = 0, den = 0;
    const counts = { full: 0, partial: 0, none: 0, missing: 0, notImpl: 0, na: 0, unset: 0 };
    for (const rc of assessable) {
      const a = assess[rc.id] || {};
      const st = a.status || "unset";
      if (st === "na") { counts.na++; continue; }
      if (st === "unset") { counts.unset++; continue; }
      if (st === "not_implemented") {
        if (rc.optional) counts.notImpl++;
        else { counts.missing++; den += 1; }
        continue;
      }
      const al = alignmentFor(rc, a);
      if (!al) { counts.full++; num += 1; den += 1; continue; }
      counts[al.level]++; num += ALIGN[al.level].score; den += 1;
    }
    const score = den ? Math.round((num / den) * 100) : null;

    const findings = [];
    for (const rc of assessable) {
      const a = assess[rc.id] || {};
      const st = a.status || "unset";
      if (st === "implemented") {
        const al = alignmentFor(rc, a);
        if (al && (al.level === "none" || al.level === "partial")) {
          const unmet = rc.criteria.filter((_, i) => !(a.checks || {})[i]);
          findings.push({ c: rc, kind: al.level, al, unmet, w: al.level === "none" ? 1 : 2 });
        }
      } else if (st === "not_implemented" && !rc.optional) {
        findings.push({ c: rc, kind: "missing", unmet: rc.criteria || [], w: 0 });
      }
    }
    findings.sort((x, y) =>
      (SEV[x.c.sev].rank - SEV[y.c.sev].rank) || (x.w - y.w) || x.c.id.localeCompare(y.c.id));

    const pocs = [];
    for (const dom of DOMAINS) {
      if (!domainApplies(dom, meta)) continue;
      if (dom.capability && caps[dom.id] === "not_implemented")
        pocs.push({ scope: dom.name, product: dom.product, text: dom.poc });
    }
    for (const c of CONTROLS) {
      if (!controlApplies(c, meta)) continue;
      const dom = DOMAINS.find((d) => d.id === c.d);
      if (dom.capability && caps[dom.id] === "not_implemented") continue;
      const rc = resolve(c, meta);
      if (rc.optional && assess[rc.id]?.status === "not_implemented")
        pocs.push({ scope: `${rc.id} · ${rc.t}`, product: rc.product, text: rc.poc });
    }

    // Per-product maturity on the Adopt -> Standardize -> Scale curve.
    const maturity = { vault: computeMaturity("vault"), terraform: computeMaturity("terraform") };

    const total = assessable.length;
    const done = total - counts.unset;
    return { assessable, score, counts, findings, pocs, total, done, maturity };

    // Gated over the already-resolved, deployment-aware assessable set.
    function computeMaturity(product) {
      const stages = {
        adopt: { met: 0, total: 0, unmet: [] },
        standardize: { met: 0, total: 0, unmet: [] },
        scale: { met: 0, total: 0, unmet: [] },
      };
      let unset = 0, inScope = 0;
      for (const rc of assessable) {
        if (rc.product !== product || !rc.stage) continue;
        const a = assess[rc.id] || {};
        const st = a.status || "unset";
        if (st === "na") continue;                          // out of scope
        if (st === "not_implemented" && rc.optional) continue; // out of scope -> PoC
        const s = stages[rc.stage];
        s.total += 1; inScope += 1;
        if (isMet(rc, a)) s.met += 1;
        else { s.unmet.push(rc); if (st === "unset") unset += 1; }
      }
      const adoptDone = stages.adopt.met === stages.adopt.total;
      const stdDone = stages.standardize.met === stages.standardize.total;
      const scaleStarted = stages.scale.met > 0;
      let pos = "adopt";
      if (adoptDone && stdDone && scaleStarted) pos = "scale";
      else if (adoptDone) pos = "standardize";
      return { stages, pos, unset, inScope, adoptDone, stdDone, scaleStarted };
    }
  }, [assess, caps, meta]);

  const sevCount = (lvl) => derived.findings.filter((f) => f.c.sev === lvl).length;

  const exportJSON = () => {
    const blob = new Blob([JSON.stringify({ meta, assess, caps, v: 3 }, null, 2)],
      { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `hashicorp-health-check-${(meta.customer || "customer").replace(/\s+/g, "-").toLowerCase()}-${meta.date}.json`;
    a.click(); URL.revokeObjectURL(url);
  };
  const importJSON = (e) => {
    const f = e.target.files?.[0]; if (!f) return;
    const r = new FileReader();
    r.onload = () => {
      try {
        const d = JSON.parse(r.result);
        if (d.meta) setMeta((m) => ({
          ...m, ...d.meta,
          vaultDeployment: d.meta.vaultDeployment || "hcp",  // v2 files default to HCP
          tfDeployment: d.meta.tfDeployment || "hcp",
        }));
        if (d.assess) setAssess(d.assess);
        if (d.caps) setCaps(d.caps);
      } catch { alert("That file could not be read as a saved assessment."); }
    };
    r.readAsText(f); e.target.value = "";
  };

  const domainProgress = (domainId) => {
    const dom = DOMAINS.find((d) => d.id === domainId);
    if (dom.capability && caps[domainId] === "not_implemented") return { done: 0, total: 0, skipped: true };
    const cs = visibleControls(domainId).filter((c) => c.resp !== "hashicorp");
    const done = cs.filter((c) => (assess[c.id]?.status || "unset") !== "unset").length;
    return { done, total: cs.length, skipped: false };
  };

  const activeDom = visibleDomains.find((d) => d.id === activeDomain) || visibleDomains[0];
  const productsInView = ["vault", "terraform"];

  return (
    <div style={{ fontFamily: "var(--sans)", color: C.ink, background: C.canvas, minHeight: "100vh" }}>
      <style>{CSS}</style>

      <header className="no-print" style={{
        position: "sticky", top: 0, zIndex: 5, background: C.primary, color: "#fff",
        borderBottom: "1px solid rgba(255,255,255,.08)",
      }}>
        <div style={{ maxWidth: 1240, margin: "0 auto", padding: "12px 22px",
          display: "flex", alignItems: "center", gap: 16, flexWrap: "wrap" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <HashiMark size={28} color="#fff" />
            <div>
              <div style={{ fontSize: 15, fontWeight: 700, letterSpacing: 0.2 }}>HashiCorp Health Check</div>
              <div style={{ fontSize: 11.5, color: "rgba(255,255,255,.62)", fontFamily: "var(--mono)" }}>
                {prodLabel("vault", meta)} · {prodLabel("terraform", meta)}
              </div>
            </div>
          </div>
          <div style={{ flex: 1 }} />
          <Seg
            value={view}
            onChange={(v) => { if (v !== "unset") setView(v); }}
            options={[
              { v: "assess", label: "Assessment", fg: C.primary, bg: "#fff" },
              { v: "report", label: `Report${derived.findings.length ? ` · ${derived.findings.length}` : ""}`, fg: C.primary, bg: "#fff" },
            ]}
          />
          <button className="btn-ghost" onClick={() => fileRef.current?.click()}>Load</button>
          <button className="btn-ghost" onClick={exportJSON}>Save</button>
          <input ref={fileRef} type="file" accept="application/json" onChange={importJSON} style={{ display: "none" }} />
        </div>
      </header>

      {view === "assess" ? (
        <div className="layout" style={{ maxWidth: 1240, margin: "0 auto", padding: "20px 22px",
          display: "grid", gridTemplateColumns: "285px 1fr", gap: 22, alignItems: "start" }}>
          <aside className="no-print sidebar" style={{ position: "sticky", top: 78 }}>
            <ScorePanel derived={derived} meta={meta} setMeta={setMeta} />
            <nav style={{ marginTop: 14 }}>
              {productsInView.map((p) => {
                const doms = visibleDomains.filter((d) => d.product === p);
                if (!doms.length) return null;
                return (
                  <div key={p} style={{ marginBottom: 12 }}>
                    <div style={{ fontSize: 11, fontWeight: 700, textTransform: "uppercase",
                      letterSpacing: 0.8, color: C.faint, padding: "4px 10px" }}>
                      {prodLabel(p, meta)}
                    </div>
                    {doms.map((d) => {
                      const pr = domainProgress(d.id);
                      const active = activeDom && activeDom.id === d.id;
                      return (
                        <button key={d.id} onClick={() => setActiveDomain(d.id)} className="navitem"
                          style={{
                            background: active ? "#fff" : "transparent",
                            borderColor: active ? C.line : "transparent",
                            boxShadow: active ? "0 1px 2px rgba(20,25,40,.06)" : "none",
                          }}>
                          <span style={{ fontWeight: active ? 650 : 500, color: active ? C.ink : C.muted }}>
                            {d.name}{d.capability ? " *" : ""}
                          </span>
                          <span style={{ fontFamily: "var(--mono)", fontSize: 11,
                            color: pr.skipped ? C.faint : (pr.done === pr.total && pr.total ? "#067647" : C.faint) }}>
                            {pr.skipped ? "skip" : `${pr.done}/${pr.total}`}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                );
              })}
              <div style={{ fontSize: 11, color: C.faint, padding: "2px 10px", lineHeight: 1.5 }}>
                * optional capability — can be marked not implemented
              </div>
            </nav>
          </aside>

          <main>
            {activeDom && (
              <>
                <div style={{ display: "flex", alignItems: "baseline", gap: 12, marginBottom: 4 }}>
                  <Badge fg={PROD[activeDom.product].fg} bg={PROD[activeDom.product].bg}>
                    {prodLabel(activeDom.product, meta)}
                  </Badge>
                  <h2 style={{ margin: 0, fontSize: 19, fontWeight: 700 }}>{activeDom.name}</h2>
                </div>

                {activeDom.capability && (
                  <CapabilityToggle dom={activeDom} value={caps[activeDom.id] || "assess"}
                    onChange={(v) => setCaps((c) => ({ ...c, [activeDom.id]: v }))} />
                )}

                {!(activeDom.capability && caps[activeDom.id] === "not_implemented") && (
                  <div style={{ marginTop: 14, display: "flex", flexDirection: "column", gap: 12 }}>
                    {visibleControls(activeDom.id).map((rc) => (
                      <ControlCard key={rc.id} c={rc} a={assess[rc.id] || {}}
                        setCtl={setCtl} toggleCheck={toggleCheck} setAllChecks={setAllChecks} />
                    ))}
                  </div>
                )}
              </>
            )}
          </main>
        </div>
      ) : (
        <Report meta={meta} derived={derived} sevCount={sevCount} />
      )}
    </div>
  );
}

function CapabilityToggle({ dom, value, onChange }) {
  return (
    <div style={{ marginTop: 12, background: "#fff", border: `1px solid ${C.line}`, borderRadius: 10,
      padding: "14px 16px", display: "flex", alignItems: "center", justifyContent: "space-between",
      gap: 16, flexWrap: "wrap" }}>
      <div>
        <div style={{ fontWeight: 650, fontSize: 13.5 }}>Is the {dom.name} capability in use?</div>
        <div style={{ fontSize: 12.5, color: C.muted, marginTop: 2, maxWidth: 560 }}>
          Mark it not implemented to skip its controls. The report then recommends a proof-of-concept instead of flagging gaps.
        </div>
      </div>
      <Seg value={value} onChange={(v) => onChange(v === "unset" ? "assess" : v)}
        options={[
          { v: "assess", label: "In use — assess", fg: "#067647", bg: "#E7F6EC" },
          { v: "not_implemented", label: "Not implemented", fg: C.muted, bg: "#EEF0F3" },
        ]} />
    </div>
  );
}

function ControlCard({ c, a, setCtl, toggleCheck, setAllChecks }) {
  const managed = c.resp === "hashicorp";
  const status = a.status || "unset";
  const al = alignmentFor(c, a);
  const allOn = al && al.done === al.total && al.total > 0;

  return (
    <div style={{ background: "#fff", border: `1px solid ${C.line}`, borderRadius: 10,
      padding: "14px 16px", opacity: managed ? 0.92 : 1 }}>
      <div style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
        <span style={{ fontFamily: "var(--mono)", fontSize: 12, fontWeight: 700, color: C.accent, marginTop: 1 }}>{c.id}</span>
        <div style={{ flex: 1 }}>
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <span style={{ fontWeight: 650, fontSize: 14.5 }}>{c.t}</span>
            <Badge fg={RESP[c.resp].fg} bg={RESP[c.resp].bg}>{RESP[c.resp].label}</Badge>
            {c.sev && <Badge fg={SEV[c.sev].fg} bg={SEV[c.sev].bg} mono>{SEV[c.sev].label}</Badge>}
            {c.stage && <Badge fg={C.muted} bg="#EEF0F3">{MATURITY[c.stage].short}</Badge>}
            {c.optional && <Badge fg={C.muted} bg="#EEF0F3">Optional</Badge>}
            {status === "implemented" && al && (
              <span style={{ marginLeft: "auto" }}>
                <Badge fg={ALIGN[al.level].fg} bg={ALIGN[al.level].bg} mono>
                  {al.done}/{al.total} · {ALIGN[al.level].label}
                </Badge>
              </span>
            )}
          </div>
          <div style={{ fontSize: 13, color: C.muted, marginTop: 5, lineHeight: 1.5 }}>{c.desc}</div>
        </div>
      </div>

      {managed ? (
        <div style={{ marginTop: 10, marginLeft: 34, fontSize: 12.5, color: C.faint,
          borderLeft: `2px solid ${C.line}`, paddingLeft: 10 }}>{c.note}</div>
      ) : (
        <div style={{ marginTop: 12, marginLeft: 34, display: "flex", flexDirection: "column", gap: 10 }}>
          <Seg size="sm" value={status}
            onChange={(v) => setCtl(c.id, { status: v === status ? "unset" : v })}
            options={[
              { v: "implemented", label: "In use", fg: "#067647", bg: "#E7F6EC" },
              { v: "not_implemented", label: "Not implemented", fg: "#B54708", bg: "#FEF0C7" },
              { v: "na", label: "N/A", fg: C.muted, bg: "#EEF0F3" },
            ]} />

          {status === "implemented" && c.criteria && (
            <div style={{ border: `1px solid ${C.line}`, borderRadius: 8, overflow: "hidden" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between",
                padding: "7px 11px", background: "#FAFBFC", borderBottom: `1px solid ${C.line}` }}>
                <span style={{ fontSize: 11.5, fontWeight: 700, textTransform: "uppercase",
                  letterSpacing: 0.5, color: C.faint }}>
                  Best-practice criteria met
                </span>
                <button className="link-btn" onClick={() => setAllChecks(c, !allOn)}>
                  {allOn ? "Clear all" : "Mark all"}
                </button>
              </div>
              {c.criteria.map((crit, i) => {
                const on = !!(a.checks || {})[i];
                return (
                  <label key={i} className="crit-row">
                    <input type="checkbox" checked={on} onChange={() => toggleCheck(c.id, i)} />
                    <span style={{ color: on ? C.ink : C.muted, fontSize: 13, lineHeight: 1.45 }}>{crit}</span>
                  </label>
                );
              })}
            </div>
          )}

          {status === "not_implemented" && c.optional && (
            <div style={{ fontSize: 12.5, color: C.muted, background: "#FBF7EE",
              border: "1px solid #F0E6D2", borderRadius: 8, padding: "8px 10px" }}>
              <strong style={{ color: "#7A5B00" }}>PoC:</strong> {c.poc}
            </div>
          )}
          {status === "not_implemented" && !c.optional && (
            <div style={{ fontSize: 12.5, color: SEV[c.sev]?.fg || C.muted }}>
              Flagged as a required control that is not present — appears in the report as a {SEV[c.sev]?.label.toLowerCase()} gap.
            </div>
          )}

          <textarea value={a.notes || ""} placeholder="Notes / evidence (optional)"
            onChange={(e) => setCtl(c.id, { notes: e.target.value })} className="notes"
            rows={a.notes ? 2 : 1} />
        </div>
      )}
    </div>
  );
}

function ScorePanel({ derived, meta, setMeta }) {
  const { score, counts, done, total } = derived;
  return (
    <div style={{ background: "#fff", border: `1px solid ${C.line}`, borderRadius: 12, padding: 16 }}>
      <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between" }}>
        <span style={{ fontSize: 12, fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.6, color: C.faint }}>Alignment</span>
        <span style={{ fontFamily: "var(--mono)", fontSize: 12, color: C.faint }}>{done}/{total} assessed</span>
      </div>
      <div style={{ fontFamily: "var(--mono)", fontSize: 40, fontWeight: 700, lineHeight: 1.1,
        marginTop: 4, color: score == null ? C.faint : C.primary }}>
        {score == null ? "—" : `${score}%`}
      </div>
      <div style={{ display: "flex", height: 8, borderRadius: 5, overflow: "hidden", background: "#EEF0F3", marginTop: 8 }}>
        <Bar n={counts.full} c="#22A366" tot={total} />
        <Bar n={counts.partial} c="#E9A23B" tot={total} />
        <Bar n={counts.none + counts.missing} c="#D2564B" tot={total} />
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: "4px 12px", marginTop: 10, fontSize: 11.5 }}>
        <Dot c="#22A366" label={`Full ${counts.full}`} />
        <Dot c="#E9A23B" label={`Partial ${counts.partial}`} />
        <Dot c="#D2564B" label={`Gap ${counts.none + counts.missing}`} />
        <Dot c={C.faint} label={`Not impl ${counts.notImpl}`} />
      </div>

      <div style={{ marginTop: 12, borderTop: `1px solid ${C.line}`, paddingTop: 12,
        display: "flex", flexDirection: "column", gap: 8 }}>
        <Field label="Customer" value={meta.customer} onChange={(v) => setMeta((m) => ({ ...m, customer: v }))} placeholder="Account name" />
        <Field label="Assessor" value={meta.assessor} onChange={(v) => setMeta((m) => ({ ...m, assessor: v }))} placeholder="Your name" />
        <div>
          <label className="fld-label">Vault deployment</label>
          <select value={meta.vaultDeployment} onChange={(e) => setMeta((m) => ({ ...m, vaultDeployment: e.target.value }))} className="select">
            <option value="hcp">HCP Vault Dedicated</option>
            <option value="enterprise">Vault Enterprise (self-managed)</option>
          </select>
        </div>
        <div>
          <label className="fld-label">Terraform deployment</label>
          <select value={meta.tfDeployment} onChange={(e) => setMeta((m) => ({ ...m, tfDeployment: e.target.value }))} className="select">
            <option value="hcp">HCP Terraform</option>
            <option value="enterprise">Terraform Enterprise (self-hosted)</option>
          </select>
        </div>
        <div>
          <label className="fld-label">Cloud</label>
          <select value={meta.cloud} onChange={(e) => setMeta((m) => ({ ...m, cloud: e.target.value }))} className="select">
            <option value="aws">AWS</option>
            <option value="azure">Azure</option>
            <option value="gcp">GCP / other</option>
          </select>
        </div>
      </div>
    </div>
  );
}

/* --- Maturity curve ------------------------------------------------ */

function nextUpText(m) {
  if (m.inScope === 0) return "No assessable controls in scope for this product.";
  const names = (list) => list.slice(0, 2).map((c) => c.t).join(", ") + (list.length > 2 ? ", …" : "");
  if (m.pos === "scale") {
    if (m.stages.scale.met === m.stages.scale.total)
      return "Every in-scope scale practice is in place.";
    return `Scaling under way — ${m.stages.scale.met}/${m.stages.scale.total} scale practices in place. Continue: ${names(m.stages.scale.unmet)}.`;
  }
  if (m.pos === "standardize") {
    if (!m.stdDone) return `To reach Scaling, finish standardizing: ${names(m.stages.standardize.unmet)}.`;
    if (m.stages.scale.unmet.length === 0)
      return "Standardized. No in-scope scale practices remain to demonstrate scaling.";
    return `Standardized. Start a scale practice to progress: ${names(m.stages.scale.unmet)}.`;
  }
  return `To reach Standardizing, complete every adopt practice: ${names(m.stages.adopt.unmet)}.`;
}

function MaturityCurve({ m }) {
  const posIdx = STAGE_ORDER.indexOf(m.pos);
  const stops = [
    { key: "adopt", x: 66, y: 118 },
    { key: "standardize", x: 250, y: 78 },
    { key: "scale", x: 434, y: 40 },
  ];
  const colorFor = (i) => (i < posIdx ? MAT_DONE : i === posIdx ? MAT_NOW : MAT_NEXT);
  const seg1Reached = posIdx >= 1;
  const seg2Reached = posIdx >= 2;

  return (
    <svg viewBox="0 0 500 168" width="100%" style={{ display: "block", maxWidth: 500, margin: "6px auto 0" }}
      role="img" aria-label={`Maturity position: ${MATURITY[m.pos].label}`}>
      <path d="M66,118 Q158,118 250,78" fill="none" strokeWidth="3" strokeLinecap="round"
        stroke={seg1Reached ? MAT_DONE : MAT_NEXT} strokeDasharray={seg1Reached ? "0" : "5 6"} />
      <path d="M250,78 Q342,78 434,40" fill="none" strokeWidth="3" strokeLinecap="round"
        stroke={seg2Reached ? MAT_DONE : MAT_NEXT} strokeDasharray={seg2Reached ? "0" : "5 6"} />

      {stops.map((s, i) => {
        const col = colorFor(i);
        const current = i === posIdx;
        const done = i < posIdx;
        const st = m.stages[s.key];
        return (
          <g key={s.key}>
            {current && <circle cx={s.x} cy={s.y} r="15" fill={MAT_NOW} opacity="0.14" />}
            <circle cx={s.x} cy={s.y} r={current ? 10 : 8}
              fill={done || current ? col : "#fff"} stroke={col} strokeWidth="2.5" />
            {done && (
              <path d={`M${s.x - 4},${s.y} l3,3 l5,-6`} fill="none" stroke="#fff" strokeWidth="2"
                strokeLinecap="round" strokeLinejoin="round" />
            )}
            <text x={s.x} y={s.y + 34} textAnchor="middle"
              style={{ fontFamily: "var(--sans)", fontSize: 13,
                fontWeight: current ? 750 : 600, fill: current ? C.ink : C.muted }}>
              {MATURITY[s.key].label}
            </text>
            <text x={s.x} y={s.y + 50} textAnchor="middle"
              style={{ fontFamily: "var(--mono)", fontSize: 11, fill: C.faint }}>
              {st.total ? `${st.met}/${st.total} met` : "—"}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

function MaturityCard({ product, m, meta }) {
  return (
    <div style={{ border: `1px solid ${C.line}`, borderRadius: 10, padding: "16px 18px", background: "#fff" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
        <Badge fg={PROD[product].fg} bg={PROD[product].bg}>{prodLabel(product, meta)}</Badge>
        <span style={{ fontSize: 16, fontWeight: 750, color: C.ink }}>{MATURITY[m.pos].label}</span>
        <span style={{ marginLeft: "auto", fontFamily: "var(--mono)", fontSize: 11, color: C.faint }}>
          {m.inScope} in scope
        </span>
      </div>

      <MaturityCurve m={m} />

      <div style={{ fontSize: 12.8, color: C.muted, marginTop: 12, lineHeight: 1.55 }}>
        <strong style={{ color: C.ink }}>Next up.</strong> {nextUpText(m)}
      </div>
      {m.unset > 0 && (
        <div style={{ fontSize: 11.5, color: C.faint, marginTop: 6, lineHeight: 1.5 }}>
          {m.unset} in-scope control{m.unset === 1 ? "" : "s"} not yet assessed; the position can rise as the assessment completes.
        </div>
      )}
    </div>
  );
}

function Report({ meta, derived, sevCount }) {
  const { findings, pocs, score, maturity } = derived;
  const managed = CONTROLS
    .filter((c) => controlApplies(c, meta))
    .map((c) => resolve(c, meta))
    .filter((rc) => rc.resp === "hashicorp");
  const scopeLine = `${prodLabel("vault", meta)} · ${prodLabel("terraform", meta)}`;

  return (
    <div className="printable" style={{ maxWidth: 900, margin: "0 auto", padding: "24px 22px 60px" }}>
      <div className="no-print" style={{ display: "flex", justifyContent: "flex-end", gap: 10, marginBottom: 12 }}>
        <button className="btn-solid" onClick={() => window.print()}>Save as PDF / Print</button>
      </div>

      <div style={{ background: "#fff", border: `1px solid ${C.line}`, borderRadius: 12, overflow: "hidden" }}>
        <div className="brandbar">
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <HashiMark size={22} color="#fff" />
            <span style={{ fontSize: 13, fontWeight: 700, letterSpacing: 0.3, color: "#fff" }}>HashiCorp</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 18 }}>
            <VaultLockup height={20} />
            <TerraformLockup height={20} />
          </div>
        </div>

        <div style={{ padding: "24px 28px 26px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start",
            borderBottom: `2px solid ${C.primary}`, paddingBottom: 16, marginBottom: 18, gap: 16 }}>
            <div>
              <div style={{ fontSize: 22, fontWeight: 800, letterSpacing: -0.2 }}>HashiCorp Health Check</div>
              <div style={{ fontSize: 13, color: C.muted, marginTop: 2 }}>
                {scopeLine} · security & governance alignment
              </div>
              <div style={{ fontSize: 12.5, color: C.muted, marginTop: 10, fontFamily: "var(--mono)" }}>
                {(meta.customer || "—")} · {meta.cloud.toUpperCase()} · {meta.date} · {(meta.assessor || "—")}
              </div>
            </div>
            <div style={{ textAlign: "right" }}>
              <div style={{ fontFamily: "var(--mono)", fontSize: 34, fontWeight: 800,
                color: score == null ? C.faint : C.primary }}>{score == null ? "—" : `${score}%`}</div>
              <div style={{ fontSize: 11, color: C.faint, textTransform: "uppercase", letterSpacing: 0.6 }}>alignment</div>
            </div>
          </div>

          <SectionTitle>Maturity position</SectionTitle>
          <div style={{ fontSize: 12.5, color: C.muted, marginTop: 6, marginBottom: 12, lineHeight: 1.55 }}>
            Position on HashiCorp's Adopt → Standardize → Scale curve, gated per product: a stage is reached only
            when every in-scope control at the earlier stages is fully aligned.
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 12, marginBottom: 24 }}>
            <MaturityCard product="vault" m={maturity.vault} meta={meta} />
            <MaturityCard product="terraform" m={maturity.terraform} meta={meta} />
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 10, marginBottom: 22 }}>
            <Stat n={sevCount("critical")} label="Critical" fg={SEV.critical.fg} bg={SEV.critical.bg} />
            <Stat n={sevCount("high")} label="High" fg={SEV.high.fg} bg={SEV.high.bg} />
            <Stat n={sevCount("medium")} label="Medium" fg={SEV.medium.fg} bg={SEV.medium.bg} />
            <Stat n={sevCount("low")} label="Low" fg={SEV.low.fg} bg={SEV.low.bg} />
          </div>

          <SectionTitle>Priority findings</SectionTitle>
          {findings.length === 0 ? (
            <Empty>No gaps recorded yet. Complete the assessment to populate this list.</Empty>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 1, marginTop: 8 }}>
              {findings.map((f, i) => (
                <div key={f.c.id} className="finding" style={{ borderTop: i ? `1px solid ${C.line}` : "none" }}>
                  <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                    <span style={{ width: 8, height: 8, borderRadius: 8, background: SEV[f.c.sev].fg, flexShrink: 0 }} />
                    <span style={{ fontFamily: "var(--mono)", fontSize: 12, fontWeight: 700, color: C.accent }}>{f.c.id}</span>
                    <span style={{ fontWeight: 650, fontSize: 14 }}>{f.c.t}</span>
                    <Badge fg={SEV[f.c.sev].fg} bg={SEV[f.c.sev].bg} mono>{SEV[f.c.sev].label}</Badge>
                    <Badge fg={PROD[f.c.product].fg} bg={PROD[f.c.product].bg}>{prodLabel(f.c.product, meta)}</Badge>
                    {f.c.stage && <Badge fg={C.muted} bg="#EEF0F3">{MATURITY[f.c.stage].short}</Badge>}
                    <span style={{ marginLeft: "auto", fontSize: 11.5, fontWeight: 650,
                      color: f.kind === "missing" ? SEV[f.c.sev].fg : ALIGN[f.kind].fg }}>
                      {f.kind === "missing" ? "Not implemented (required)"
                        : `${f.al.done}/${f.al.total} · ${ALIGN[f.kind].label}`}
                    </span>
                  </div>
                  <div style={{ fontSize: 12.8, color: C.muted, marginTop: 6, lineHeight: 1.55, paddingLeft: 18 }}>
                    <strong style={{ color: C.ink }}>Why it matters.</strong> {f.c.why}
                  </div>
                  {f.unmet.length > 0 && (
                    <div style={{ paddingLeft: 18, marginTop: 6 }}>
                      <div style={{ fontSize: 11.5, fontWeight: 700, color: C.ink, marginBottom: 3 }}>
                        {f.kind === "missing" ? "Best practices to implement" : "Criteria not yet met"}
                      </div>
                      <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12.6, color: C.muted, lineHeight: 1.5 }}>
                        {f.unmet.map((u, j) => <li key={j}>{u}</li>)}
                      </ul>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          <SectionTitle style={{ marginTop: 26 }}>Proof-of-concept recommendations</SectionTitle>
          {pocs.length === 0 ? (
            <Empty>No capabilities marked not implemented.</Empty>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 10, marginTop: 8 }}>
              {pocs.map((p, i) => (
                <div key={i} style={{ background: "#FBF7EE", border: "1px solid #F0E6D2", borderRadius: 8, padding: "11px 13px" }}>
                  <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    <Badge fg={PROD[p.product].fg} bg={PROD[p.product].bg}>{prodLabel(p.product, meta)}</Badge>
                    <span style={{ fontWeight: 650, fontSize: 13 }}>{p.scope}</span>
                  </div>
                  <div style={{ fontSize: 12.8, color: "#6B5626", marginTop: 5, lineHeight: 1.5 }}>{p.text}</div>
                </div>
              ))}
            </div>
          )}

          <SectionTitle style={{ marginTop: 26 }}>Managed by HashiCorp (informational)</SectionTitle>
          {managed.length === 0 ? (
            <div style={{ fontSize: 12.5, color: C.muted, marginTop: 6, lineHeight: 1.6 }}>
              Self-managed deployment: platform, storage, seal, and network controls are in your scope and
              appear as scored controls above. No controls are HashiCorp-managed for this selection.
            </div>
          ) : (
            <div style={{ fontSize: 12.5, color: C.muted, marginTop: 6, lineHeight: 1.6 }}>
              {managed.map((c) => `${c.id} ${c.t}`).join(" · ")}. These are handled by the managed platform and
              are not scored. Confirm current tier and configuration with HashiCorp where a compliance attestation
              depends on them.
            </div>
          )}

          <div style={{ marginTop: 24, borderTop: `1px solid ${C.line}`, paddingTop: 12, fontSize: 11, color: C.faint, lineHeight: 1.5 }}>
            Draft health check derived from the customer Vault Enterprise Security Benchmark, adapted per deployment,
            plus authored Terraform and self-hosted operations controls. Alignment is computed from the best-practice
            criteria ticked per control. Severity tiers are a proposed model for review.
          </div>
        </div>
      </div>
    </div>
  );
}

function Bar({ n, c, tot }) { return <div style={{ width: `${tot ? (n / tot) * 100 : 0}%`, background: c }} />; }
function Dot({ c, label }) {
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 5, color: C.muted }}>
      <span style={{ width: 8, height: 8, borderRadius: 8, background: c }} />{label}
    </span>
  );
}
function Field({ label, value, onChange, placeholder }) {
  return (
    <div>
      <label className="fld-label">{label}</label>
      <input value={value} placeholder={placeholder} onChange={(e) => onChange(e.target.value)} className="input" />
    </div>
  );
}
function Stat({ n, label, fg, bg }) {
  return (
    <div style={{ background: bg, borderRadius: 10, padding: "12px 14px" }}>
      <div style={{ fontFamily: "var(--mono)", fontSize: 26, fontWeight: 800, color: fg }}>{n}</div>
      <div style={{ fontSize: 11.5, fontWeight: 650, color: fg, textTransform: "uppercase", letterSpacing: 0.4 }}>{label}</div>
    </div>
  );
}
function SectionTitle({ children, style }) {
  return <div style={{ fontSize: 12, fontWeight: 800, textTransform: "uppercase", letterSpacing: 1, color: C.primary, ...style }}>{children}</div>;
}
function Empty({ children }) { return <div style={{ fontSize: 13, color: C.faint, marginTop: 8, fontStyle: "italic" }}>{children}</div>; }
function today() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

const CSS = `
  :root{
    --sans: system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    --mono: ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
  }
  *{ box-sizing:border-box; }
  button{ font-family:var(--sans); }
  .btn-ghost{ background:rgba(255,255,255,.1); color:#fff; border:1px solid rgba(255,255,255,.18);
    border-radius:8px; padding:7px 13px; font-size:12.5px; font-weight:600; cursor:pointer; }
  .btn-ghost:hover{ background:rgba(255,255,255,.18); }
  .btn-solid{ background:${C.accent}; color:#fff; border:none; border-radius:8px; padding:9px 16px; font-size:13px; font-weight:650; cursor:pointer; }
  .btn-solid:hover{ background:#3647a8; }
  .link-btn{ background:none; border:none; color:${C.accent}; font-size:11.5px; font-weight:650; cursor:pointer; padding:0; }
  .link-btn:hover{ text-decoration:underline; }
  .navitem{ width:100%; display:flex; align-items:center; justify-content:space-between; gap:8px; text-align:left;
    border:1px solid transparent; border-radius:8px; padding:7px 10px; margin:1px 0; cursor:pointer; background:transparent; font-size:13px; }
  .navitem:hover{ background:#fff; }
  .crit-row{ display:flex; gap:10px; align-items:flex-start; padding:8px 11px; cursor:pointer; border-top:1px solid ${C.line}; }
  .crit-row:first-of-type{ border-top:none; }
  .crit-row:hover{ background:#FAFBFC; }
  .crit-row input{ margin-top:2px; width:15px; height:15px; accent-color:${C.accent}; cursor:pointer; flex-shrink:0; }
  .input,.select{ width:100%; border:1px solid ${C.line}; border-radius:7px; padding:6px 9px; font-size:13px; font-family:var(--sans); color:${C.ink}; background:#fff; }
  .input:focus,.select:focus,.notes:focus{ outline:2px solid ${C.accentSoft}; border-color:${C.accent}; }
  .fld-label{ display:block; font-size:11px; font-weight:650; color:${C.faint}; text-transform:uppercase; letter-spacing:.4px; margin-bottom:3px; }
  .notes{ width:100%; border:1px solid ${C.line}; border-radius:7px; padding:7px 9px; font-size:12.5px; font-family:var(--sans); color:${C.ink}; resize:vertical; }
  .finding{ padding:12px 4px; }
  .brandbar{ background:${C.primary}; display:flex; align-items:center; justify-content:space-between;
    gap:16px; padding:12px 28px; flex-wrap:wrap;
    -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  @media (max-width: 820px){
    .layout{ grid-template-columns:1fr !important; }
    .sidebar{ position:static !important; }
  }
  @media print{
    .no-print{ display:none !important; }
    body{ background:#fff; }
    .printable{ max-width:100% !important; padding:0 !important; }
    .printable > div{ border:none !important; }
    *{ -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  }
`;
