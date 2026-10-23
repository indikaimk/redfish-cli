# redfish-tool

A Go CLI for exploring Huawei server management controllers
through the Redfish API. It uses Go's standard library and does not assume that
every server or BMC firmware exposes the same optional resources.

## Requirements

- Go 1.24 or later
- A Huawei server/BMC reachable over HTTP(S); authenticated commands require a
  Redfish account, but `scan` is anonymous

## Build

```sh
go build -o redfish ./cmd/redfish
```

On Windows PowerShell, build with:

```powershell
go build -o redfish.exe ./cmd/redfish
```

## Credentials

Provide credentials through environment variables. The password is intentionally
not accepted as a command-line flag, where it could be exposed in process
listings or shell history.

```sh
export REDFISH_USERNAME='your-user'
export REDFISH_PASSWORD='your-password'
```

In Windows PowerShell, set them for the current session with:

```powershell
$env:REDFISH_USERNAME = 'your-user'
$env:REDFISH_PASSWORD = 'your-password'
```

These values are available to commands run from that PowerShell window and are
cleared when it closes. Then run the CLI, for example:

```powershell
.\redfish.exe discover --endpoint https://192.0.2.10
```

TLS certificate verification is enabled by default. For a lab controller with
a self-signed certificate, `--insecure` explicitly disables verification; do
not use it on untrusted networks. HTTP is supported for controllers that require
it, but does not encrypt credentials or traffic; prefer HTTPS.

## Commands

```sh
redfish discover --endpoint https://192.0.2.10
redfish systems --endpoint https://192.0.2.10
redfish get --endpoint https://192.0.2.10 /redfish/v1/Chassis
```

- `discover` prints the Redfish service root and its advertised links.
- `systems` reads the Systems collection and then each advertised system.
- `get` reads any absolute Redfish resource path on the configured controller.

### Scan a subnet or IP range into a YAML inventory

Scan only networks you are authorized to access. `scan` makes an anonymous
HTTPS GET to `/redfish/v1` on port 443 for each target. It does not use
`REDFISH_USERNAME` or `REDFISH_PASSWORD`, even when they are set, and it makes no
configuration changes.

```powershell
.\redfish.exe scan --target 10.174.89.0/24 --output inventory.yaml --insecure
```

Or use an inclusive start-end IPv4 range:

```powershell
.\redfish.exe scan --target 10.174.89.16-10.174.89.50 `
  --output inventory-range.yaml --insecure
```

TLS verification is enabled unless `--insecure` is supplied. Discovery reads
`UUID` and `Oem.Huawei.ProductName` directly from the service root; it does not
query protected manager or system resources or guess blade IDs.

Example inventory:

```yaml
version: 1
hosts:
  - ip: "10.174.89.16"
    endpoint: "https://10.174.89.16"
    status: "discovered"
    uuid: "5FCA285B-0488-B3E0-E911-9335CE76F877"
    product_name: "CH121 V5"
failures:
  - ip: "10.174.89.17"
    endpoint: "https://10.174.89.17"
    status: "authentication_required"
    error: "GET /redfish/v1 returned HTTP 401 Unauthorized: "
```

- Limits: at most 1024 addresses, 8 concurrent hosts, and 5 seconds per request.
  Larger ranges/subnets are rejected before any requests are sent.
- CIDRs are normalized to their subnet. Network and broadcast addresses are
  excluded for `/30` and larger subnets; `/31` and `/32` include every address.
  Explicit ranges include both endpoints.
- Only validated Redfish service roots appear under `hosts`. Missing UUID or
  ProductName is recorded as an empty string and reported on stderr.
- Other results appear under `failures`, with a diagnostic: authentication
  required (401), forbidden (403), HTTP errors, certificate errors, connection
  errors, timeouts, invalid responses, or cancelled requests. A connection error
  or timeout does not prove the IP is unused; the HTTPS endpoint may be filtered.
- Output is ordered by IP and contains no credentials. Existing inventory files
  are never overwritten; choose a new filename for subsequent scans.
- Per-host failures do not stop the scan. Completion reports counts on stderr;
  output-file errors and interruption return an error. Ctrl+C saves results
  collected so far and records cancelled targets.

This inventory is for discovery only; bulk syslog configuration from YAML is
not implemented yet.

### Configure syslog forwarding

Huawei BMCs may expose a manager-specific `SyslogService` resource. Select the
target explicitly with `--manager` (for example, `Blade7`); the command does not
assume that blade numbering is the same across chassis and never updates every
blade automatically. Use `get` first to check that manager's supported values:

```powershell
.\redfish.exe get --endpoint https://192.0.2.10 /redfish/v1/Managers/Blade7/SyslogService
```

Configure a syslog server slot with a dry run first:

```powershell
.\redfish.exe syslog --endpoint https://192.0.2.10 `
  --manager Blade7 --server 0 `
  --address 172.26.103.27 --port 6514 `
  --protocol TCP --message-format RFC3164 `
  --log-types "OperationLog,SecurityLog,EventLog" --enable
```

The dry run prints the proposed PATCH body without changing the BMC. Add
`--apply` to send the PATCH and read the service back for verification. The
command reads the current configuration first and preserves the other server
slots. Omitted protocol, message format, and log types are left unchanged.
Slots are selected by `MemberId` (0-3); `--disable` disables only the selected
slot. `--enable` requires an address and port.

When the BMC supplies an `ETag` response header (or `@odata.etag` in the
resource), the command sends that exact version in the PATCH `If-Match` header.
This supports BMCs that require conditional updates and helps prevent overwriting
concurrent configuration changes. HTTP 412 means the BMC rejected a precondition;
review the current configuration before rerunning the command. The command does
not retry automatically or force an overwrite. If no ETag is provided, the PATCH
is sent without `If-Match`; a BMC requiring it may still reject the request.

```powershell
.\redfish.exe syslog --endpoint https://192.0.2.10 `
  --manager Blade7 --server 0 `
  --address 172.26.103.27 --port 6514 `
  --protocol TCP --message-format RFC3164 --enable --apply
```

Syslog configuration changes BMC settings. Confirm the manager, server address,
port, and options against the BMC UI and firmware documentation before applying.
The syslog feature uses a Huawei-specific Redfish resource and may not be
available or accept identical values on every firmware version. All other
commands remain read-only.
