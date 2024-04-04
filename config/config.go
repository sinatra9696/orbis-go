package config

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// Config aggregates all the configuration options.
// It is data only, and minimal to none external dependencies.
// This implies only native types, and no external dependencies.
type Config struct {
	GRPC      GRPC
	Host      Host
	Cosmos    Cosmos
	DKG       DKG
	Logger    Logger
	Ring      Ring
	Secret    Secret
	Transport Transport
	Bulletin  Bulletin
	DB        DB
	Authz     Authz
}

type Authz struct {
	Address string `default:"127.0.0.1:8080" description:"GRPC server address"`
}

type Logger struct {
	Level string `default:"debug" description:"Log level"`
}

type GRPC struct {
	GRPCURL string `default:"127.0.0.1:8080" description:"gRPC URL"`
	RESTURL string `default:"127.0.0.1:8090" description:"REST URL"`
	Logging bool   `default:"false" description:"debug mode"`
	Utility bool   `default:"false" description:"Enable the utility service (demo and test ONLY)"`
}

type DKG struct {
	Repo      string `default:"simpledb" description:"DKG repo"`
	Transport string `default:"p2ptp" description:"DKG transport"`
	Bulletin  string `default:"p2pbb" description:"DKG Bulletin"`
}

type Cosmos struct {
	AccountName    string `default:"" description:"Account name"`
	AddressPrefix  string `default:"" description:"Address prefix"`
	KeyringBackend string `default:"os" description:"Keyring backend"`
	Home           string `default:"" description:"Cosmos home directory"`
	Fees           string `default:"" description:"Fees"`
	RPCAddress     string `default:"" description:"RPC address"`
}

type Ring struct {
}

type Secret struct {
}

type Transport struct {
	Rendezvous string `default:"orbis-transport" description:"Rendezvous string"`
}

type Bulletin struct {
	P2P struct {
		PersistentPeers string `default:"" description:"comma seperated list of persistent peer multiaddrs"`
		Rendezvous      string `default:"orbis-bulletin" description:"Rendezvous string"`
	}
}

type Host struct {
	Crypto struct {
		Type string `default:"secp256k1" description:"crypto type"`
		Bits int    `default:"-1" description:"crypto bits, if selectable"`
		Seed int    `default:"0" description:"crypto seed (TESTING ONLY)"`
	}
	ListenAddresses []string `default:"/ip4/0.0.0.0/tcp/9000" description:"Host listen address string"`
	BootstrapPeers  []string `mapstructure:"bootstrap_peers" default:"" description:"Comma separated multiaddr strings of bootstrap peers. If empty, the node will run in bootstrap mode"`
	// Rendezvous      string   `default:"orbis" description:"Rendezvous string"`
}

type DB struct {
	Path string `default:"data" description:"DB path"`
}

type configTypes interface {
	Host | Cosmos | DB | Bulletin | Transport | Secret | Ring | DKG | GRPC | Logger
}

func Default[T configTypes]() (T, error) {
	valT := new(T)

	x := reflect.ValueOf(valT).Elem()
	err := traverseAndBuildDefault(x)
	if err != nil {
		return *valT, fmt.Errorf("traverse: %w", err)
	}
	return *valT, nil
}

func traverseAndBuildDefault(v reflect.Value) error {
	// ensure struct
	for i := 0; i < v.NumField(); i++ {

		field := v.Type().Field(i)
		name, tag := field.Name, field.Tag

		f := v.Field(i)
		if !f.CanSet() {
			return fmt.Errorf("can't set field %s", name)
		}

		kind := f.Kind()

		// Generate the Cobra command flag.
		val, _ := tag.Get("default"), tag.Get("description")

		var err error
		var defaultValue any
		switch kind {
		case reflect.Struct:
			x := reflect.New(f.Type()).Elem()
			err := traverseAndBuildDefault(x)
			if err != nil {
				return fmt.Errorf("traverse: %w", err)
			}
			f.Set(x)
			continue
		case reflect.Bool:
			defaultValue, err = strconv.ParseBool(val)
			if err != nil {
				return fmt.Errorf("parseBool: %q, %w", val, err)
			}
		case reflect.String:
			// cmd.Flags().String(snake, val, desc)
			defaultValue = val
		case reflect.Int:
			defaultValue, err = strconv.Atoi(val)
			if err != nil {
				return fmt.Errorf("parseBool: %q, %w", val, err)
			}
			// cmd.Flags().Int(snake, parsed, desc)
		case reflect.Uint:
			defaultValue, err = strconv.ParseUint(val, 10, 64)
			if err != nil {
				return fmt.Errorf("parseBool: %q, %w", val, err)
			}
			// cmd.Flags().Uint(snake, uint(parsed), desc)
		case reflect.Float64:
			defaultValue, err = strconv.ParseFloat(val, 64)
			if err != nil {
				return fmt.Errorf("parseBool: %q, %w", val, err)
			}
			// cmd.Flags().Float64(snake, parsed, desc)
		case reflect.Slice:
			// TODO: support other slice types.
			elmType := f.Type().Elem().Kind()
			if elmType != reflect.String {
				return fmt.Errorf("unsupported slice type: %q, for entry: %q", elmType, name)
			}
			// cmd.Flags().StringSlice(snake, strings.Split(val, ","), desc)
			defaultValue = strings.Split(val, ",")
		default:
			return fmt.Errorf("unsupported type: %q, for entry: %q", kind, name)
		}
		f.Set(reflect.ValueOf(defaultValue))
	}

	return nil
}
