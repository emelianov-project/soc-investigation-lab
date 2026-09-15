# Synthetic Windows Event Fixtures

All telemetry in this directory is synthetic and hand-authored for repeatable automated tests
and educational lab use. None of the fixtures originates from an employer, client, production
environment, or real incident. Names, identifiers, SIDs, GUIDs, timestamps, process IDs, and
ports are fixed and fictitious. Network values use documentation-safe address space and
`example.com` names.

The fixtures contain no real credentials, secrets, personal information, or sensitive data. They
are intended to support later Windows Event XML ingestion and normalization work; they are not
application parser implementations or incident evidence. Adding real production logs to this
directory is prohibited.

## Fixture manifest

| Source | Event ID | Description | File |
| --- | ---: | --- | --- |
| Windows Security | 4624 | Successful logon | `security/security_4624_successful_logon.xml` |
| Windows Security | 4625 | Failed logon | `security/security_4625_failed_logon.xml` |
| Windows Security | 4688 | Process creation | `security/security_4688_process_creation.xml` |
| Sysmon | 1 | Process creation | `sysmon/sysmon_1_process_creation.xml` |
| Sysmon | 3 | Network connection | `sysmon/sysmon_3_network_connection.xml` |
| Sysmon | 11 | File creation | `sysmon/sysmon_11_file_create.xml` |
| Sysmon | 22 | DNS query | `sysmon/sysmon_22_dns_query.xml` |
