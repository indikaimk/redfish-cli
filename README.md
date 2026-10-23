# redfish-tool

A Go CLI for exploring Huawei server management controllers through the Redfish
API. It uses age for encrypted credential storage and does not assume that every
server or BMC firmware exposes the same optional resources.

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

Provide credentials through an encrypted credential file (below) or environment
variables. BMC passwords and vault passphrases are intentionally not accepted as
command-line flags, where they could be exposed in process listings or shell
history.

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

### Encrypted credentials for hosts with different passwords

The app integrates [age](https://age-encryption.org/) passphrase encryption;
you do not need to install age separately. One encrypted file can hold multiple
credentials, each selected by a reference and bound to a specific BMC endpoint.
The file is decrypted in memory, never into a plaintext temporary file.

#### 1. Create the file and add the first host

Run from an interactive PowerShell terminal:

```powershell
.\redfish.exe credentials set --file .\credentials.age `
  --ref host-16 --endpoint https://10.174.89.16 --username your-user
```

You will be prompted for:

1. A vault passphrase, entered twice.
2. That BMC's password, entered twice.

Input is hidden. Choose a long, unique vault passphrase and keep it in a password
manager, separately from the encrypted file. There is no recovery if it is lost.
Do not put passwords or the passphrase in command arguments, scripts, or YAML.
Redirected/piped password input is deliberately not supported.

#### 2. Add more hosts

Use the same file and vault passphrase, with a different reference and endpoint:

```powershell
.\redfish.exe credentials set --file .\credentials.age `
  --ref host-17 --endpoint https://10.174.89.17 --username another-user
```

The existing file must unlock successfully before it can be updated. Other
entries are preserved. Both the vault passphrase and BMC password are confirmed
on every `credentials set` command.

To update a stored credential, repeat its command with `--replace` and enter
the existing vault passphrase and the new BMC password. This updates local
storage only; it does **not** change the password on the BMC. `--replace` is also
required to change an existing reference's username or endpoint. This command
does not change the vault passphrase.

#### 3. Use a stored credential

```powershell
.\redfish.exe discover --endpoint https://10.174.89.16 `
  --credentials-file .\credentials.age --credential-ref host-16
```

Enter the vault passphrase once for that invocation. Both vault flags are
supported by `discover`, `systems`, `get`, and `syslog`. For `get`, place all flags
before the resource path:

```powershell
.\redfish.exe get --endpoint https://10.174.89.16 `
  --credentials-file .\credentials.age --credential-ref host-16 `
  /redfish/v1/Managers
```

For syslog, first preview the configuration, then repeat with `--apply`:

```powershell
.\redfish.exe syslog --endpoint https://10.174.89.16 `
  --credentials-file .\credentials.age --credential-ref host-16 `
  --manager Blade6 --server 0 --address 172.26.103.27 --port 6514 `
  --protocol TCP --message-format RFC3164 --enable
```

Use the endpoint's actual manager ID rather than assuming `Blade6` on every
server. A missing reference, incorrect passphrase, damaged vault, or endpoint
mismatch stops the command without using environment credentials or trying
another entry. Vault mode ignores `REDFISH_USERNAME` and `REDFISH_PASSWORD`;
an explicit `--username` cannot be combined with vault mode.

The stored endpoint must match the command's scheme, hostname/IP, and explicit
port. Hostname case and a trailing slash are normalized; DNS aliases, an IP and
hostname, or an implicit and explicit port are not considered equivalent.
Without vault flags, existing environment-variable authentication is unchanged.
`scan` remains anonymous and does not open the credential file.

#### Storage and operational precautions

- Only encrypted data is written to disk, including temporary files used during
  updates. Updates are synced and renamed into place; failed decryption does not
  overwrite the existing vault. Keep a secure backup before making changes.
- An adjacent `.lock` file prevents overlapping updates using the same path.
  If a process crashes and leaves it behind, confirm no updater is running
  before removing **only that lock file**. Avoid editing through alternate
  paths or syncing the vault while updating it.
- Unix files are created owner-only (`0600`). On Windows, use a private folder
  with NTFS permissions limited to your account; Unix mode bits do not enforce
  Windows ACLs. Keep vaults and backups out of source control. The repository
  ignores `*.age` and `*.age.lock`; use additional ignore rules if you choose
  another extension.
- Encryption protects credentials at rest, not from malware, administrators, or
  inspection of the running process. Temporary byte buffers are cleared where
  practical, but Go cannot guarantee every copy of a secret is erased.
- Use trusted HTTPS certificates. `--insecure` disables BMC identity verification;
  encrypted local storage cannot prevent credentials being sent to an impersonator.
- This is an interactive workflow, not an unattended secret service. There are
  no plaintext export, passphrase environment-variable, or plaintext import
  options.

YAML inventory ingestion and bulk configuration are not implemented yet.
For now, choose the reference explicitly with `--credential-ref`; inventory
files continue to contain no credentials.

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

Failures are written separately to `inventory.failures.yaml` (or
`inventory-range.failures.yaml` for the second example), not mixed into the
inventory or printed individually on stderr. Use `--failures-output` to choose
a different path:

```powershell
.\redfish.exe scan --target 10.174.89.0/24 --output inventory.yaml `
  --failures-output scan-errors.yaml --insecure
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
```

Example failures file:

```yaml
version: 1
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
- Other results appear under `failures` in the separate failures file, with a diagnostic: authentication
  required (401), forbidden (403), HTTP errors, certificate errors, connection
  errors, timeouts, invalid responses, or cancelled requests. A connection error
  or timeout does not prove the IP is unused; the HTTPS endpoint may be filtered.
- Both files are ordered by IP and contain no credentials. Neither file is
  overwritten; choose new filenames for subsequent scans. Both paths must be
  writable and unused before scanning starts. The failures file is created even
  when there are no failures (`failures: []`).
- Per-host failures do not stop the scan. Completion reports counts on stderr;
  output-file errors and interruption return an error. Ctrl+C saves results
  collected so far and records cancelled targets in the failures file.

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
Redfish commands remain read-only. `credentials set` only changes the local
encrypted credential file.
