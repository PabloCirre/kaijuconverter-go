# Security Policy

KaijuConverter takes information security, user confidentiality, and memory safety seriously across all our open-source tools, client SDKs, extensions, and public infrastructure.

## Supported Versions

| Package / Project | Version | Supported |
|:------------------|:--------|:----------|
| `kaijuconverter-go` | `main` branch / Latest Release | :white_check_mark: |
| Cloud API (`api.kaijuconverter.com`) | `v1` | :white_check_mark: |

## Reporting a Vulnerability

If you identify a security vulnerability in this repository or the [KaijuConverter Platform](https://kaijuconverter.com), please do **not** open a public GitHub issue. Instead, report it through our responsible disclosure channels:

1. **Security Overview & Disclosure Policy**: [https://kaijuconverter.com/security](https://kaijuconverter.com/security)
2. **RFC 9116 Machine-Readable Security Contact**: [https://kaijuconverter.com/.well-known/security.txt](https://kaijuconverter.com/.well-known/security.txt)
3. **API Documentation & Security Headers**: [https://kaijuconverter.com/api-docs](https://kaijuconverter.com/api-docs)
4. **Email Security Team**: `security@kaijuconverter.com` (GPG key available via `security.txt`)

### Vulnerability Response Service Level Agreement (SLA)

- **Initial Triage Acknowledgement**: Within 24 hours.
- **Vulnerability Assessment & Severity Scoring**: Within 72 hours (CVSS v3.1 standard).
- **Patch Deployment & Coordinated Disclosure**: 7 to 30 business days depending on severity level.

## Architecture & Data Safety Guarantees

- **Zero Data Retention Policy**: All temporary files processed via KaijuConverter are encrypted at rest using AES-256-GCM and irreversibly purged within 60 minutes of task completion.
- **TLS 1.3 Transport Security**: All API endpoints enforce strict HSTS and TLS 1.3 encryption.
- **Sandboxed Processing**: Conversion workers run inside ephemeral, unprivileged Linux namespaces with seccomp-bpf system call filters and memory quotas.

Thank you for helping keep [KaijuConverter](https://kaijuconverter.com) safe for millions of users worldwide!
