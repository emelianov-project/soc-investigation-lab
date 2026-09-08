# Security and Safe Data Handling Policy

## Purpose

This policy protects SOC Investigation Lab from accidentally publishing credentials, secrets, confidential information, production security telemetry, corporate or internal data, personal data, and unsafe malicious content.

SOC Investigation Lab is a defensive-security education and portfolio project. Its examples and investigation material must use controlled data that is safe for public distribution.

## Public Repository Assumption

SOC Investigation Lab is a public repository. Contributors must assume that anything committed may become:

- publicly visible;
- cloned or forked;
- cached or indexed; and
- retained in Git history.

Sensitive information must never be committed on the assumption that deleting it later will fully reverse the exposure.

## Prohibited Sensitive Data

Never commit:

- production secrets, passwords, authentication tokens, or API keys;
- private cryptographic keys or session tokens and cookies;
- real corporate logs or production telemetry;
- confidential enterprise data or internal infrastructure details;
- personal data or real customer data; or
- confidential incident-response evidence.

This prohibition applies to source code, configuration, documentation, test fixtures, screenshots, datasets, examples, investigation artifacts, and attachments to Issues or Pull Requests. Do not include a real sensitive value even as an example.

## Secrets and Credentials

Do not commit any of the following:

- passwords;
- API keys;
- access or refresh tokens;
- OAuth secrets;
- GitHub personal access tokens;
- cloud or database credentials;
- private SSH keys;
- private TLS or certificate key material;
- signing keys;
- webhook secrets;
- session cookies;
- authorization headers; or
- connection strings containing credentials.

Documentation must use obvious placeholders such as `<api-key>`, `<token>`, `<password>`, or `<redacted>`. Do not create realistic-looking secret values unnecessarily.

A real credential or secret that is accidentally committed must be treated as compromised.

## Production and Corporate Telemetry

Real corporate or production telemetry must not be used as source data for this repository. The following are prohibited:

- real production Windows Event Logs;
- real production Sysmon logs;
- real SIEM or EDR exports;
- corporate log archives;
- internal SOC alerts from real organizations;
- real incident-response evidence;
- production packet captures or memory dumps;
- production endpoint artifacts;
- internal screenshots containing corporate data;
- confidential infrastructure configuration; and
- data copied from an employer, client, or customer environment.

Real employer, client, corporate, or production telemetry remains prohibited even after manual or ad-hoc anonymization, sanitization, or redaction. Sanitized employer or production logs are not acceptable source datasets.

When realistic examples are needed, recreate the relevant behavior with synthetic events, telemetry generated in a controlled lab, or public datasets that are clearly safe and permitted for redistribution.

## Personal and Confidential Information

Do not include unnecessary real-world personal information, including:

- real names or personal email addresses;
- phone numbers;
- real account identifiers;
- usernames or device identifiers tied to real people;
- employee identifiers; or
- customer identifiers.

Do not publish private organization-specific information such as internal DNS names, production asset names, private tenant or subscription identifiers, internal ticket or incident numbers, or private network descriptions copied from a real organization.

Use fictional people, organizations, accounts, hosts, and identifiers in training scenarios.

## Safe Dataset Requirements

Preferred dataset origins are, in order:

1. Fully synthetic data generated specifically for this project.
2. Telemetry generated in a controlled personal or lab environment created specifically for testing.
3. Public sample data that is clearly suitable and permitted for public reuse.

The term "sanitized" does not grant permission to import real employer, client, corporate, or production telemetry after ad-hoc redaction. Such telemetry remains prohibited.

A safe dataset must contain no credentials, secrets, personal data, customer information, confidential corporate identifiers, or proprietary enterprise content.

For every future dataset, contributors should be able to document:

- its source or origin;
- whether it is synthetic, lab-generated, or public;
- any sanitization performed when relevant; and
- why it is safe for public distribution.

Dataset provenance and safety assumptions should be documented alongside the data when datasets are introduced.

## Malicious Samples and Payloads

SOC Investigation Lab is defensive and investigation-focused. Do not commit live executable malware or operational malicious payloads, including:

- malware or ransomware binaries;
- droppers or credential stealers;
- destructive payloads;
- executable shellcode;
- live malicious scripts intended to compromise systems;
- weaponized exploit bundles;
- files designed to execute harmful behavior;
- active command-and-control configuration; or
- direct malware-download artifacts.

Tests, scripts, CI, setup commands, and development tools must not automatically download or execute malicious content.

Permitted defensive representations may include synthetic event records, inert text fixtures, hashes, filenames, metadata, fictional command lines, MITRE ATT&CK mappings, non-executable behavioral descriptions, and benign lab-generated simulations.

Prefer behavior simulation and resulting telemetry over storing actual malware.

## Safe Example Values

Examples must use clearly fictional or reserved values.

- Use domains such as `example.com`, `example.org`, and `example.net`.
- Use IPv4 documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`.
- Use IPv6 documentation prefix `2001:db8::/32`.
- Use fictional usernames, hostnames, organizations, and identifiers.

Do not copy real corporate or internal values into synthetic fixtures or examples.

## Pre-Commit Safety Review

Before committing telemetry, datasets, screenshots, fixtures, or investigation artifacts, verify that:

- the source is synthetic, controlled-lab, or clearly public-safe;
- no corporate or production logs are included;
- no credential or secret exists;
- no personal data exists;
- no confidential organization identifier exists;
- no harmful executable sample exists;
- example names and addresses are fictional or reserved;
- hidden metadata does not expose sensitive information where relevant; and
- the content is necessary for the linked Issue.

If there is uncertainty about whether information is safe to publish, do not commit it. Use synthetic replacement data instead.

## Accidental Sensitive Data Exposure

If sensitive information is accidentally committed:

1. Stop further use or publication of the exposed value.
2. Treat an exposed real secret or credential as compromised.
3. Revoke or rotate it through the appropriate provider or system.
4. Notify the repository maintainer privately when sensitive details are involved.
5. Remove the sensitive material from the repository and Git history where appropriate.
6. Review related files and commits for additional exposure.
7. Do not assume that deleting the latest file or adding a follow-up commit makes the original exposure safe.

History rewriting cannot guarantee removal from every existing clone, fork, or cache. Credential revocation or rotation remains necessary.

## Vulnerability Reporting

Private vulnerability reporting is currently disabled for this repository. Security Advisories are available to maintainers, but that does not provide arbitrary reporters with a private GitHub reporting form.

### Sensitive security vulnerability

If a report contains exploit-sensitive details, credentials, confidential data, or reproduction material that should not be public:

- do not publish those details in a public GitHub Issue;
- use an available private maintainer contact channel if one exists;
- repository maintainers may use GitHub Security Advisories for coordinated private remediation and discussion where appropriate; and
- if no private contact channel is known, create only a minimal public Issue requesting a private reporting channel, without exploit details, credentials, or sensitive evidence.

### Non-sensitive security improvement

Security hardening suggestions that contain no sensitive exploit or confidential information may be reported through a normal GitHub Issue.

When safe, a useful report may identify the affected component or path, affected commit or version, security impact, high-level reproduction conditions, and a possible mitigation.

Never include real credentials, confidential third-party data, customer data, or production evidence. This project does not promise a bug bounty, response service-level agreement, response time, or remediation deadline.

## Project Security Boundaries

SOC Investigation Lab is educational, portfolio-oriented, and focused on defensive security. It is not a production security product and does not provide production-grade security guarantees.

Product boundaries are defined in [Project Scope](docs/project-scope.md), contribution practices in the [Contributing Guide](CONTRIBUTING.md), and high-level technical boundaries in [System Architecture](docs/architecture/overview.md).
