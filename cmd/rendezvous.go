// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fido-device-onboard/go-fdo-server/internal/handlers/rendezvous"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// RendezvousConfig server configuration (TBD)
type RendezvousConfig struct{}

// RendezvousServerConfig server configuration file structure
type RendezvousServerConfig struct {
	FDOServerConfig `mapstructure:",squash"`
	DeviceCAConfig  DeviceCAConfig   `mapstructure:"device_ca"`
	Rendezvous      RendezvousConfig `mapstructure:"rendezvous"`
}

// validate checks that required configuration is present
func (rv *RendezvousServerConfig) validate() error {
	slog.Debug("Validating HTTP configuration")
	if err := rv.HTTP.validate(); err != nil {
		slog.Error("HTTP configuration validation failed", "err", err)
		return err
	}
	slog.Debug("HTTP configuration valid")

	if rv.DeviceCAConfig.CertPath != "" {
		slog.Debug("Device CA certificate path configured", "path", rv.DeviceCAConfig.CertPath)
	} else {
		slog.Warn("Device CA certificate path not configured - voucher verification may fail")
	}

	return nil
}

// rendezvousCmd represents the rendezvous command
var rendezvousCmd = &cobra.Command{
	Use:   "rendezvous http_address",
	Short: "Serve an instance of the rendezvous server",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		slog.Debug("Binding rendezvous command flags")
		// Rebind only those keys needed by the rendezvous command. This is
		// necessary because Viper cannot bind the same key twice and
		// the other sub commands use the same keys.
		if err := viper.BindPFlag("device_ca.cert", cmd.Flags().Lookup("device-ca-cert")); err != nil {
			slog.Error("Failed to bind device-ca-cert flag", "err", err)
			return err
		}
		slog.Debug("Successfully bound rendezvous command flags")
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		slog.Info("Starting rendezvous server initialization")
		var rvConfig RendezvousServerConfig
		if err := viper.Unmarshal(&rvConfig); err != nil {
			slog.Error("Failed to unmarshal rendezvous config", "err", err)
			return fmt.Errorf("failed to unmarshal rendezvous config: %w", err)
		}
		slog.Debug("Parsed rendezvous configuration", "config", rvConfig)

		slog.Debug("Validating rendezvous configuration")
		if err := rvConfig.validate(); err != nil {
			slog.Error("Rendezvous configuration validation failed", "err", err)
			return fmt.Errorf("failed to validate config: %w", err)
		}
		slog.Info("Rendezvous configuration validated successfully")

		slog.Info("Parsed Config:", "rvConfig", fmt.Sprintf("%+v", rvConfig))
		return serveRendezvous(&rvConfig)
	},
}

// RendezvousServer represents the HTTP server
type RendezvousServer struct {
	handler http.Handler
	config  HTTPConfig
}

// NewRendezvousServer creates a new Server
func NewRendezvousServer(config HTTPConfig, handler http.Handler) *RendezvousServer {
	return &RendezvousServer{handler: handler, config: config}
}

// Start starts the HTTP server
func (s *RendezvousServer) Start() error {
	slog.Debug("Configuring HTTP server")
	srv := &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: 3 * time.Second,
	}

	// Channel to listen for interrupt or terminate signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	slog.Debug("Signal handlers registered for graceful shutdown")

	// Goroutine to listen for signals and gracefully shut down the server
	go func() {
		sig := <-stop
		slog.Info("Received shutdown signal, initiating graceful shutdown", "signal", sig)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			slog.Error("Error during server shutdown", "err", err)
		} else {
			slog.Info("Server shutdown completed successfully")
		}
	}()

	// Listen and serve
	slog.Debug("Creating TCP listener", "addr", s.config.ListenAddress())
	lis, err := net.Listen("tcp", s.config.ListenAddress())
	if err != nil {
		slog.Error("Failed to create TCP listener", "addr", s.config.ListenAddress(), "err", err)
		return fmt.Errorf("failed to create TCP listener: %w", err)
	}
	defer func() { _ = lis.Close() }()
	slog.Info("Server listening on TCP", "addr", lis.Addr().String())

	if s.config.UseTLS() {
		slog.Info("Starting HTTPS server", "cert", s.config.CertPath, "key", s.config.KeyPath)
		preferredCipherSuites := []uint16{
			tls.TLS_AES_256_GCM_SHA384,                  // TLS v1.3
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,   // TLS v1.2
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, // TLS v1.2
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, // TLS v1.2
		}
		srv.TLSConfig = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			CipherSuites: preferredCipherSuites,
		}
		slog.Debug("TLS configuration applied", "minVersion", "TLS 1.2")
		err = srv.ServeTLS(lis, s.config.CertPath, s.config.KeyPath)
		if err != nil && err != http.ErrServerClosed {
			slog.Error("HTTPS server error", "err", err)
			return fmt.Errorf("HTTPS server error: %w", err)
		}
		slog.Info("HTTPS server stopped")
		return nil
	}
	slog.Info("Starting HTTP server (no TLS)")
	err = srv.Serve(lis)
	if err != nil && err != http.ErrServerClosed {
		slog.Error("HTTP server error", "err", err)
		return fmt.Errorf("HTTP server error: %w", err)
	}
	slog.Info("HTTP server stopped")
	return nil
}

func serveRendezvous(config *RendezvousServerConfig) error {
	slog.Info("Initializing rendezvous server")

	slog.Debug("Initializing database connection", "type", config.DB.Type, "dsn", config.DB.DSN)
	dbState, err := config.DB.getState()
	if err != nil {
		slog.Error("Failed to initialize database", "err", err)
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	slog.Info("Database initialized successfully", "type", config.DB.Type)

	// Add trusted device CA certificates to the database
	slog.Debug("Loading device CA certificate", "path", config.DeviceCAConfig.CertPath)
	deviceCACerts, err := config.DeviceCAConfig.getDeviceCACertsAsPEM()
	if err != nil {
		slog.Error("Failed to read device CA certificate", "path", config.DeviceCAConfig.CertPath, "err", err)
		return fmt.Errorf("failed to get device CA cert as PEM: %w", err)
	}
	slog.Debug("Device CA certificate loaded successfully")

	slog.Debug("Importing device CA certificate to database")
	stats, err := dbState.ImportDeviceCACertificates(context.Background(), deviceCACerts)
	if err != nil {
		slog.Error("Failed to import device CA certificate", "err", err)
		return fmt.Errorf("failed to import device CA certificate: %w", err)
	}
	slog.Info("Device CA certificate import completed",
		"detected", stats.Detected,
		"imported", stats.Imported,
		"skipped", stats.Skipped,
		"malformed", stats.Malformed)

	slog.Debug("Loading trusted device CA certificates into memory")
	if err = dbState.LoadTrustedDeviceCAs(context.Background()); err != nil {
		slog.Error("Failed to load trusted device CAs", "err", err)
		return fmt.Errorf("failed to load trusted device CAs: %w", err)
	}
	slog.Info("Trusted device CA certificates loaded into memory successfully")

	slog.Debug("Creating rendezvous handler")
	rendezvous := rendezvous.NewRendezvous(dbState)
	handler := rendezvous.Handler()
	slog.Debug("Rendezvous handler created successfully")

	// Listen and serve
	slog.Debug("Creating HTTP server", "addr", config.HTTP.ListenAddress(), "tls", config.HTTP.UseTLS())
	server := NewRendezvousServer(config.HTTP, handler)

	slog.Info("Starting rendezvous server", "addr", config.HTTP.ListenAddress())
	return server.Start()
}

// Set up the rendezvous command line. Used by the unit tests to reset state between tests.
func rendezvousCmdInit() {
	rootCmd.AddCommand(rendezvousCmd)
	rendezvousCmd.Flags().String("device-ca-cert", "", "Device CA certificate path")
}

func init() {
	rendezvousCmdInit()
}
