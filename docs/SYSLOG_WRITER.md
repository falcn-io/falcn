# Syslog Audit Writer

Falcn's audit logger supports forwarding structured security events to any RFC 5424-compliant
syslog destination. This is used by security operations centres (SOC), SIEM integrations
(Splunk, Elastic, QRadar), and compliance audit trails.

---

## Overview

The `SyslogAuditWriter` wraps Falcn's internal `AuditLogger` and writes every scan event,
threat detection, policy violation, and auth event to syslog in structured RFC 5424 format.

**Supported transport protocols:**

| Protocol | Use Case |
|----------|----------|
| `udp` | Low-latency, best-effort (default; suitable for local rsyslog) |
| `tcp` | Reliable delivery for remote syslog servers |
| `tls` | Encrypted delivery for compliance environments |
| `stdout` | Local development and container logging (stdout) |
| `file` | Write to a local log file path |

---

## Message Format (RFC 5424)

Each audit event is written as a structured syslog message:

```
<PRI>1 TIMESTAMP HOSTNAME APP_NAME PID MSGID STRUCTURED_DATA MESSAGE
```

Example threat detection event:
```
<131>1 2026-03-07T14:23:01.000Z prod-scanner-01 falcn 4821 THREAT_DETECTED
  [falcn@48577 package="lodash" version="4.17.11" severity="critical"
   type="vulnerable" cve="CVE-2019-10744" reachable="true"]
  Malicious package detected: lodash@4.17.11 — prototype pollution (CVE-2019-10744)
```

**Syslog severity mapping:**

| Falcn Level | Syslog Severity |
|-------------|----------------|
| `CRITICAL`  | 2 (Critical)   |
| `ERROR`     | 3 (Error)      |
| `HIGH`      | 4 (Warning)    |
| `MEDIUM`    | 5 (Notice)     |
| `LOW`       | 6 (Info)       |
| `DEBUG`     | 7 (Debug)      |

---

## Configuration

### Environment Variables

```bash
FALCN_SYSLOG_ENABLED=true
FALCN_SYSLOG_PROTOCOL=udp           # udp | tcp | tls | stdout | file
FALCN_SYSLOG_ADDRESS=127.0.0.1:514  # host:port (ignored for stdout/file)
FALCN_SYSLOG_APP_NAME=falcn
FALCN_SYSLOG_FACILITY=local0        # user | local0 - local7 | or integer 0-23
FALCN_SYSLOG_FILE_PATH=/var/log/falcn/audit.log  # only for file protocol
```

### YAML Config

```yaml
audit:
  syslog:
    enabled: true
    protocol: tcp          # udp | tcp | tls | stdout | file
    address: "siem.internal:514"
    app_name: falcn
    hostname: ""           # Leave empty to auto-detect hostname
    facility: local0       # syslog facility
    tls:
      enabled: false
      ca_cert: /etc/ssl/certs/siem-ca.pem
      client_cert: ""
      client_key: ""
      insecure_skip_verify: false
    file_path: ""          # Only used when protocol: file
    buffer_size: 1000      # In-memory event buffer (thread-safe)
    flush_interval: 5s     # How often to flush buffered events
```

### Programmatic Usage (Go)

```go
writer, err := security.NewSyslogAuditWriter(map[string]interface{}{
    "protocol": "udp",
    "address":  "127.0.0.1:514",
    "app_name": "falcn",
    "facility": "local0",
})
if err != nil {
    log.Fatalf("syslog init failed: %v", err)
}
defer writer.Close()

logger := security.NewAuditLogger(writer)
logger.LogThreatDetected(ctx, threat)
```

---

## Event Types

All audit events include a `MSGID` field that identifies the event type:

| MSGID | Description |
|-------|-------------|
| `THREAT_DETECTED` | A threat was found during a scan |
| `SCAN_STARTED` | A new scan began |
| `SCAN_COMPLETED` | A scan finished (includes summary counts) |
| `POLICY_VIOLATION` | A Rego policy blocked a package |
| `AUTH_SUCCESS` | Successful API authentication |
| `AUTH_FAILURE` | Failed authentication attempt |
| `RATE_LIMIT_HIT` | Request rejected due to rate limiting |
| `CONFIG_CHANGED` | Configuration was modified |
| `REPORT_GENERATED` | A compliance report was generated |

---

## Integration Examples

### rsyslog (local)

`/etc/rsyslog.d/falcn.conf`:
```
# Receive Falcn UDP events and write to dedicated log file
$template FalcnFormat,"%TIMESTAMP:::date-rfc3339% %HOSTNAME% %syslogtag% %msg%\n"
if $programname == 'falcn' then /var/log/falcn/audit.log;FalcnFormat
& stop
```

Reload: `systemctl restart rsyslog`

### Splunk Universal Forwarder

`inputs.conf`:
```ini
[monitor:///var/log/falcn/audit.log]
disabled = false
index = security
sourcetype = falcn:audit
```

Or use Splunk HEC directly — see [INTEGRATIONS.md](INTEGRATIONS.md#splunk-hec).

### Elastic / OpenSearch

Configure Filebeat to tail `/var/log/falcn/audit.log`:
```yaml
filebeat.inputs:
  - type: log
    paths:
      - /var/log/falcn/audit.log
    fields:
      service: falcn
      env: production
    json.keys_under_root: true

output.elasticsearch:
  hosts: ["https://elastic.internal:9200"]
  index: "falcn-audit-%{+yyyy.MM.dd}"
```

### QRadar

Point a QRadar log source at the syslog UDP/TCP port where Falcn is sending.
Set source type to `Universal DSM` and map `MSGID` field for event correlation.

---

## TLS Configuration

For encrypted syslog (e.g., to a remote SIEM over the public internet):

```yaml
audit:
  syslog:
    enabled: true
    protocol: tls
    address: "siem.example.com:6514"
    tls:
      enabled: true
      ca_cert: /etc/falcn/tls/siem-ca.pem
      client_cert: /etc/falcn/tls/falcn-client.pem
      client_key: /etc/falcn/tls/falcn-client-key.pem
```

Generate a self-signed cert for testing:
```bash
openssl req -x509 -newkey rsa:4096 -keyout falcn-client-key.pem \
  -out falcn-client.pem -days 365 -nodes \
  -subj "/CN=falcn-audit-client"
```

---

## Troubleshooting

| Problem | Likely Cause | Fix |
|---------|-------------|-----|
| No events arriving | Syslog disabled | Set `FALCN_SYSLOG_ENABLED=true` |
| `connection refused` | Wrong address/port | Verify `FALCN_SYSLOG_ADDRESS` and firewall rules |
| Events dropping | UDP packet loss | Switch to `protocol: tcp` |
| TLS handshake failure | Certificate mismatch | Check CA cert and server CN |
| Log file not created | Directory missing | `mkdir -p /var/log/falcn && chmod 750 /var/log/falcn` |
| Missing events under load | Buffer overflow | Increase `buffer_size` and `flush_interval` |
