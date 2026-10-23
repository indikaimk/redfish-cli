# redfish-tool

A Go CLI for exploring Huawei server management controllers
through the Redfish API. It uses Go's standard library and does not assume that
every server or BMC firmware exposes the same optional resources.

## Requirements

- Go 1.24 or later
- A Huawei server/BMC reachable over HTTP(S) with a Redfish account

## Build

```sh
go build -o redfish ./cmd/redfish
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
