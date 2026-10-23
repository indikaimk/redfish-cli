package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"redfish-tool/internal/redfish"
)

const serviceRootPath = "/redfish/v1"

type options struct {
	endpoint         string
	username         string
	insecure         bool
	credentialsFile  string
	credentialRef    string
	usernameExplicit bool
}

type syslogOptions struct {
	manager              string
	serverID             string
	address              string
	port                 int
	logTypes             string
	transmissionProtocol string
	messageFormat        string
	enable               bool
	disable              bool
	apply                bool
}

type collection struct {
	Members *[]struct {
		ODataID string `json:"@odata.id"`
	} `json:"Members"`
}

type syslogService struct {
	ETag          string                       `json:"@odata.etag"`
	SyslogServers []map[string]json.RawMessage `json:"SyslogServers"`
}

type serviceRoot struct {
	Systems struct {
		ODataID string `json:"@odata.id"`
	} `json:"Systems"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageError()
	}
	if args[0] == "scan" {
		return runScan(args[1:])
	}
	if args[0] == "credentials" {
		return runCredentials(args[1:], promptSecret)
	}

	command := args[0]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	opts := options{}
	flags.StringVar(&opts.endpoint, "endpoint", "", "BMC origin, for example https://192.0.2.10")
	flags.StringVar(&opts.username, "username", os.Getenv("REDFISH_USERNAME"), "Redfish username (or set REDFISH_USERNAME)")
	flags.BoolVar(&opts.insecure, "insecure", false, "skip TLS certificate verification (not recommended)")
	flags.StringVar(&opts.credentialsFile, "credentials-file", "", "age-encrypted credential file")
	flags.StringVar(&opts.credentialRef, "credential-ref", "", "credential reference bound to this endpoint")

	switch command {
	case "discover", "systems":
	case "syslog":
		syslogOpts := syslogOptions{}
		flags.StringVar(&syslogOpts.manager, "manager", "", "manager ID, for example Blade7 (required)")
		flags.StringVar(&syslogOpts.serverID, "server", "0", "syslog server slot MemberId (0-3)")
		flags.StringVar(&syslogOpts.address, "address", "", "syslog server hostname or IP address")
		flags.IntVar(&syslogOpts.port, "port", 0, "syslog server port (1-65535)")
		flags.StringVar(&syslogOpts.logTypes, "log-types", "", "comma-separated log types to forward")
		flags.StringVar(&syslogOpts.transmissionProtocol, "protocol", "", "transmission protocol: UDP, TCP, or TLS")
		flags.StringVar(&syslogOpts.messageFormat, "message-format", "", "message format: RFC3164, RFC5424, or Custom")
		flags.BoolVar(&syslogOpts.enable, "enable", false, "enable the selected syslog server")
		flags.BoolVar(&syslogOpts.disable, "disable", false, "disable the selected syslog server")
		flags.BoolVar(&syslogOpts.apply, "apply", false, "apply the changes (default is dry-run)")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		opts.usernameExplicit = flagsHasUsername(flags)
		if flags.NArg() != 0 {
			return usageError()
		}
		if err := validateSyslogOptions(syslogOpts); err != nil {
			return err
		}
		return execute(opts, command, "", syslogOpts)
	case "get":
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		opts.usernameExplicit = flagsHasUsername(flags)
		if flags.NArg() != 1 {
			return fmt.Errorf("get requires one resource path, such as /redfish/v1/Systems")
		}
		return execute(opts, command, flags.Arg(0), syslogOptions{})
	default:
		return usageError()
	}

	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	opts.usernameExplicit = flagsHasUsername(flags)
	if flags.NArg() != 0 {
		return usageError()
	}
	return execute(opts, command, "", syslogOptions{})
}

func flagsHasUsername(flags *flag.FlagSet) bool {
	found := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "username" {
			found = true
		}
	})
	return found
}

func execute(opts options, command, resourcePath string, syslogOpts syslogOptions) error {
	if opts.endpoint == "" {
		return fmt.Errorf("--endpoint is required")
	}
	if strings.HasPrefix(strings.ToLower(opts.endpoint), "http://") {
		fmt.Fprintln(os.Stderr, "warning: HTTP does not encrypt Redfish credentials or traffic")
	}
	credential, err := resolveCredentials(opts, promptSecret)
	if err != nil {
		return err
	}
	client, err := redfish.NewClient(redfish.Config{
		Endpoint:       opts.endpoint,
		Username:       credential.Username,
		Password:       credential.Password,
		Insecure:       opts.insecure,
		RequestTimeout: 30 * time.Second,
	})
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()

	ctx := context.Background()
	switch command {
	case "discover":
		data, err := client.Get(ctx, serviceRootPath)
		if err != nil {
			return err
		}
		return printJSON(data)
	case "get":
		data, err := client.Get(ctx, resourcePath)
		if err != nil {
			return err
		}
		return printJSON(data)
	case "systems":
		return printSystems(ctx, client)
	case "syslog":
		return executeSyslog(ctx, client, syslogOpts)
	default:
		return usageError()
	}
}

func validateSyslogOptions(opts syslogOptions) error {
	if opts.manager == "" || strings.IndexFunc(opts.manager, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_')
	}) != -1 {
		return fmt.Errorf("syslog requires a valid --manager ID, such as Blade7")
	}
	if len(opts.serverID) != 1 || opts.serverID < "0" || opts.serverID > "3" {
		return fmt.Errorf("--server must be a slot from 0 to 3")
	}
	if opts.enable == opts.disable {
		return fmt.Errorf("specify exactly one of --enable or --disable")
	}
	if opts.enable && (strings.TrimSpace(opts.address) == "" || opts.port < 1 || opts.port > 65535) {
		return fmt.Errorf("--enable requires --address and --port from 1 to 65535")
	}
	if opts.disable && (opts.address != "" || opts.port != 0) {
		return fmt.Errorf("--address and --port cannot be used with --disable")
	}
	if opts.transmissionProtocol != "" && !contains([]string{"UDP", "TCP", "TLS"}, opts.transmissionProtocol) {
		return fmt.Errorf("--protocol must be UDP, TCP, or TLS")
	}
	if opts.messageFormat != "" && !contains([]string{"RFC3164", "RFC5424", "Custom"}, opts.messageFormat) {
		return fmt.Errorf("--message-format must be RFC3164, RFC5424, or Custom")
	}
	if opts.logTypes != "" {
		for _, logType := range strings.Split(opts.logTypes, ",") {
			logType = strings.TrimSpace(logType)
			if !contains([]string{"OperationLog", "SecurityLog", "EventLog"}, logType) {
				return fmt.Errorf("unsupported log type %q; use OperationLog, SecurityLog, or EventLog", logType)
			}
		}
	}
	return nil
}

func executeSyslog(ctx context.Context, client *redfish.Client, opts syslogOptions) error {
	resourcePath := "/redfish/v1/Managers/" + opts.manager + "/SyslogService"
	data, etag, err := client.GetWithETag(ctx, resourcePath)
	if err != nil {
		return err
	}

	var service syslogService
	if err := json.Unmarshal(data, &service); err != nil {
		return fmt.Errorf("decode syslog service: %w", err)
	}
	if etag == "" {
		etag = service.ETag
	}
	if service.SyslogServers == nil {
		return fmt.Errorf("syslog service does not contain a SyslogServers array")
	}

	serverIndex := -1
	for i := range service.SyslogServers {
		var memberID string
		if err := json.Unmarshal(service.SyslogServers[i]["MemberId"], &memberID); err != nil {
			return fmt.Errorf("decode MemberId for syslog server slot %d: %w", i, err)
		}
		if memberID == opts.serverID {
			serverIndex = i
			break
		}
	}
	if serverIndex == -1 {
		return fmt.Errorf("syslog service does not contain server slot %s", opts.serverID)
	}

	server := service.SyslogServers[serverIndex]
	if err := setSyslogField(server, "Enabled", opts.enable); err != nil {
		return err
	}
	if opts.enable {
		if err := setSyslogField(server, "Address", strings.TrimSpace(opts.address)); err != nil {
			return err
		}
		if err := setSyslogField(server, "Port", opts.port); err != nil {
			return err
		}
	}
	if opts.logTypes != "" {
		if err := setSyslogField(server, "LogType", splitLogTypes(opts.logTypes)); err != nil {
			return err
		}
	}

	payload := map[string]any{"SyslogServers": service.SyslogServers}
	if opts.enable {
		payload["ServiceEnabled"] = true
	}
	if opts.transmissionProtocol != "" {
		payload["TransmissionProtocol"] = opts.transmissionProtocol
	}
	if opts.messageFormat != "" {
		payload["MessageFormat"] = opts.messageFormat
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode syslog configuration: %w", err)
	}
	if !opts.apply {
		fmt.Fprintln(os.Stderr, "Dry run: no changes sent. Add --apply to apply this configuration.")
		return printJSON(encoded)
	}

	if err := client.Patch(ctx, resourcePath, encoded, etag); err != nil {
		return err
	}
	updated, err := client.Get(ctx, resourcePath)
	if err != nil {
		return fmt.Errorf("configuration was patched but could not be verified: %w", err)
	}
	return printJSON(updated)
}

func setSyslogField(fields map[string]json.RawMessage, name string, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode syslog field %s: %w", name, err)
	}
	fields[name] = encoded
	return nil
}

func splitLogTypes(value string) []string {
	items := strings.Split(value, ",")
	for i := range items {
		items[i] = strings.TrimSpace(items[i])
	}
	return items
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func printSystems(ctx context.Context, client *redfish.Client) error {
	systems, err := fetchSystems(ctx, client)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(systems)
	if err != nil {
		return fmt.Errorf("encode systems: %w", err)
	}
	return printJSON(encoded)
}

func fetchSystems(ctx context.Context, client *redfish.Client) ([]json.RawMessage, error) {
	rootData, err := client.Get(ctx, serviceRootPath)
	if err != nil {
		return nil, err
	}
	var root serviceRoot
	if err := json.Unmarshal(rootData, &root); err != nil {
		return nil, fmt.Errorf("decode service root: %w", err)
	}
	if root.Systems.ODataID == "" {
		return nil, fmt.Errorf("service root does not advertise a Systems resource")
	}

	collectionData, err := client.Get(ctx, root.Systems.ODataID)
	if err != nil {
		return nil, fmt.Errorf("read systems collection: %w", err)
	}
	var systemsCollection collection
	if err := json.Unmarshal(collectionData, &systemsCollection); err != nil {
		return nil, fmt.Errorf("decode systems collection: %w", err)
	}
	if systemsCollection.Members == nil {
		return nil, fmt.Errorf("systems collection does not contain a Members array")
	}

	systems := make([]json.RawMessage, 0, len(*systemsCollection.Members))
	for _, member := range *systemsCollection.Members {
		if member.ODataID == "" {
			return nil, fmt.Errorf("systems collection contains a member without @odata.id")
		}
		system, err := client.Get(ctx, member.ODataID)
		if err != nil {
			return nil, fmt.Errorf("read system %s: %w", member.ODataID, err)
		}
		systems = append(systems, system)
	}
	return systems, nil
}

func printJSON(data []byte) error {
	var formatted json.RawMessage
	if err := json.Unmarshal(data, &formatted); err != nil {
		return fmt.Errorf("decode JSON for output: %w", err)
	}
	output, err := json.MarshalIndent(formatted, "", "  ")
	if err != nil {
		return fmt.Errorf("format JSON: %w", err)
	}
	fmt.Println(string(output))
	return nil
}

func usageError() error {
	return fmt.Errorf("usage: redfish <discover|systems|get|syslog> --endpoint https://BMC [--username USER] [--insecure]\nauthenticate with REDFISH_PASSWORD and REDFISH_USERNAME/--username, or --credentials-file FILE --credential-ref NAME\nredfish credentials set --file credentials.age --ref NAME --endpoint https://BMC --username USER [--replace]\nredfish scan --target CIDR_OR_START-END --output inventory.yaml [--failures-output failures.yaml] [--insecure]\nget takes a Redfish resource path")
}
