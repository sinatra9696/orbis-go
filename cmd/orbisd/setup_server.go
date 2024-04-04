package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sourcenetwork/orbis-go/config"
	"github.com/sourcenetwork/orbis-go/pkg/util/cleaner"

	logging "github.com/ipfs/go-log"
	"golang.org/x/sync/errgroup"
)

func setupServer(cfg config.Config) error {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clnr := cleaner.New()
	defer clnr.CleanUp()

	setupLogger(cfg)

	app, err := setupApp(ctx, cfg)
	if err != nil {
		return fmt.Errorf("setup app: %w", err)
	}

	// Errgroup tracks long running goroutines.
	// Any of the goroutines returns an error, the errgroup will return the error.
	errGrp, errGrpCtx := errgroup.WithContext(ctx)

	// Expose app services via gRPC server.
	err = setupGRPCServer(cfg.GRPC, errGrp, clnr, app)
	if err != nil {
		return fmt.Errorf("setup gRPC server: %w", err)
	}

	// load existing ring state
	log.Info("Loading rings from state")
	err = app.LoadRings(ctx)
	if err != nil {
		return fmt.Errorf("loading rings: %w", err)
	}

	// Catch and handle signals
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		var sig os.Signal
		select {
		case sig = <-sigs:
			log.Infof("Received signal %q", sig)
		case <-errGrpCtx.Done():
			// At least 1 managed goroutines returns an error.
		}
		cancel()
		clnr.CleanUp()
	}()

	// Wait for all goroutines to finish.
	return errGrp.Wait()
}

func setupLogger(cfg config.Config) error {
	_, err := logging.LevelFromString(cfg.Logger.Level)
	if err != nil {
		return fmt.Errorf("invalid log level '%s'", cfg.Logger.Level)
	}

	logging.SetAllLoggers(logging.LevelDPanic)
	logging.SetLogLevelRegex("orbis.*", cfg.Logger.Level)

	// dht is really chatty
	err = logging.SetLogLevelRegex("dht/.*", "error")
	if err != nil {
		return fmt.Errorf("set dht log level: %w", err)
	}

	return nil
}
