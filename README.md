# redfish-tool

A read-only Go CLI starter for exploring Huawei server management controllers
through the Redfish API. It uses Go's standard library and does not assume that
every server or iBMC firmware exposes the same optional resources.

## Requirements

- Go 1.24 or later
- A Huawei server/iBMC reachable over HTTP(S) with a Redfish account

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

All commands are read-only. No configuration, reset, or power actions are
implemented yet. Validate resource support against the target server and BMC
firmware before adding write operations.
