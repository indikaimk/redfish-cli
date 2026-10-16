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
	endpoint string
	username string
	insecure bool
}

type collection struct {
	Members *[]struct {
		ODataID string `json:"@odata.id"`
	} `json:"Members"`
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

	command := args[0]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	opts := options{}
	flags.StringVar(&opts.endpoint, "endpoint", "", "BMC origin, for example https://192.0.2.10")
	flags.StringVar(&opts.username, "username", os.Getenv("REDFISH_USERNAME"), "Redfish username (or set REDFISH_USERNAME)")
	flags.BoolVar(&opts.insecure, "insecure", false, "skip TLS certificate verification (not recommended)")

	switch command {
	case "discover", "systems":
	case "get":
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 1 {
			return fmt.Errorf("get requires one resource path, such as /redfish/v1/Systems")
		}
		return execute(opts, command, flags.Arg(0))
	default:
		return usageError()
	}

	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return usageError()
	}
	return execute(opts, command, "")
}

func execute(opts options, command, resourcePath string) error {
	if opts.endpoint == "" {
		return fmt.Errorf("--endpoint is required")
	}
	if strings.HasPrefix(strings.ToLower(opts.endpoint), "http://") {
		fmt.Fprintln(os.Stderr, "warning: HTTP does not encrypt Redfish credentials or traffic")
	}
	client, err := redfish.NewClient(redfish.Config{
		Endpoint:       opts.endpoint,
		Username:       opts.username,
		Password:       os.Getenv("REDFISH_PASSWORD"),
		Insecure:       opts.insecure,
		RequestTimeout: 30 * time.Second,
	})
	if err != nil {
		return err
	}

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
	default:
		return usageError()
	}
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
	return fmt.Errorf("usage: redfish <discover|systems|get> --endpoint https://BMC [--username USER] [--insecure]\nset REDFISH_PASSWORD (and optionally REDFISH_USERNAME); get takes a Redfish resource path")
}
