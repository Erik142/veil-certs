package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	"github.com/Erik142/veil-certs/pkg/castore/file"
	"github.com/Erik142/veil-certs/pkg/certgen"
	"github.com/Erik142/veil-certs/pkg/keyprovider/plaintext"
	pb "github.com/Erik142/veil-certs/pkg/proto"
	"github.com/Erik142/veil-certs/pkg/server"
)

func main() {
	// 1. Initialize Viper for configuration
	viper.SetConfigName("config")    // Name of config file (without extension)
	viper.SetConfigType("yaml")      // Type of config file
	viper.AddConfigPath("./configs") // Path to look for the config file
	viper.AutomaticEnv()             // Read environment variables
	viper.SetEnvPrefix("veilcerts")  // Environment variables should be like VEILCERTS_GRPC_PORT
	viper.SetDefault("log.level", "info")

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; ignore error if we're only using environment variables
			fmt.Println("No config file found, relying on environment variables or defaults.")
		} else {
			logrus.Fatalf("Fatal error reading config file: %v", err)
		}
	}

	// Set up Logrus
	log := logrus.New()
	log.SetOutput(os.Stdout)
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	logLevel := viper.GetString("log.level")
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		log.Fatalf("Invalid log level '%s': %v", logLevel, err)
	}
	log.SetLevel(level)
	entry := log.WithField("service", "NebulaCertService")

	grpcPort := viper.GetInt("grpc.port")
	entry.Infof("Starting Nebula Certificate Service on port :%d", grpcPort)

	// Initialize components based on Viper config
	caCertPath := viper.GetString("ca.cert_path")
	caKeyPath := viper.GetString("ca.key_path")
	caPassphrase := viper.GetString("ca.passphrase") // Can be empty if not encrypted or provided by ENV
	encryptCaKey := viper.GetBool("ca.encrypt_key")
	caCommonName := viper.GetString("ca.common_name")
	caDurationDays := viper.GetInt("ca.duration_days")
	caSubnet := viper.GetString("ca.subnet")

	// Passphrase provider
	passphraseProvider := plaintext.NewPlainTextPassphraseProvider(caPassphrase)

	// CA Store
	caStore := file.NewFileCAStore(caCertPath, caKeyPath)

	// Certificate Generator
	certGenerator, err := certgen.NewCertGenerator(caSubnet)

	if err != nil {
		panic(err)
	}

	// Check if CA exists, if not, generate it
	if !caStore.CAExists() {
		entry.Warn("CA certificate and key not found. Generating new CA...")
		caPair, err := certGenerator.GenerateCACertificate(
			caCommonName,
			time.Duration(caDurationDays)*24*time.Hour,
			encryptCaKey,
			passphraseProvider,
			caSubnet,
		)
		if err != nil {
			entry.Fatalf("Failed to generate CA certificate: %v", err)
		}
		if err := caStore.SaveCA(caPair.CertPEM, caPair.KeyPEM); err != nil {
			entry.Fatalf("Failed to save generated CA certificate and key: %v", err)
		}
		entry.Info("New CA certificate and key generated and saved.")
	} else {
		entry.Info("Existing CA certificate and key found. Loading...")
	}

	// Set up gRPC server
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", grpcPort))
	if err != nil {
		entry.Fatalf("Failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterCertificateServiceServer(grpcServer, server.NewCertificateServiceServer(caStore, passphraseProvider, certGenerator))

	// Start gRPC server in a goroutine
	go func() {
		entry.Infof("gRPC server listening on %v", lis.Addr())
		if err := grpcServer.Serve(lis); err != nil {
			entry.Fatalf("gRPC server failed to serve: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	entry.Info("Shutting down gRPC server...")
	grpcServer.GracefulStop()
	entry.Info("gRPC server stopped.")
}
