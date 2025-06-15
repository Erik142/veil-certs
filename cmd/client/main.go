package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/Erik142/veil-certs/pkg/proto"
)

func main() {
	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewCertificateServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	req := &pb.GenerateHostCertificateRequest{
		Hostname:        "test-host-1",
		IpCidr:          "",
		Groups:          []string{"test-group", "dev"},
		DurationSeconds: int64((90 * 24 * time.Hour).Seconds()),
	}

	log.Printf("Requesting certificate for host: %s", req.Hostname)
	res, err := c.GenerateHostCertificate(ctx, req)
	if err != nil {
		log.Fatalf("could not generate host certificate: %v", err)
	}

	fmt.Println("\n--- Generated Host Certificate (PEM) ---")
	fmt.Println(string(res.CertPem))
	fmt.Println("--- Generated Host Private Key (PEM) ---")
	fmt.Println(string(res.KeyPem))

	keyPath := fmt.Sprintf("%s.key", req.Hostname)
	certPath := fmt.Sprintf("%s.crt", req.Hostname)

	if err := os.WriteFile(keyPath, res.KeyPem, 0600); err != nil {
		panic(fmt.Errorf("failed to write CA key: %w", err))
	}
	if err := os.WriteFile(certPath, res.CertPem, 0644); err != nil {
		panic(fmt.Errorf("failed to write CA cert: %w", err))
	}

	req = &pb.GenerateHostCertificateRequest{
		Hostname:        "test-host-2",
		IpCidr:          "",
		Groups:          []string{"test-group", "dev"},
		DurationSeconds: int64((90 * 24 * time.Hour).Seconds()),
	}

	log.Printf("Requesting certificate for host: %s", req.Hostname)
	res, err = c.GenerateHostCertificate(ctx, req)
	if err != nil {
		log.Fatalf("could not generate host certificate: %v", err)
	}

	fmt.Println("\n--- Generated Host Certificate (PEM) ---")
	fmt.Println(string(res.CertPem))
	fmt.Println("--- Generated Host Private Key (PEM) ---")
	fmt.Println(string(res.KeyPem))

	keyPath = fmt.Sprintf("%s.key", req.Hostname)
	certPath = fmt.Sprintf("%s.crt", req.Hostname)

	if err := os.WriteFile(keyPath, res.KeyPem, 0600); err != nil {
		panic(fmt.Errorf("failed to write CA key: %w", err))
	}
	if err := os.WriteFile(certPath, res.CertPem, 0644); err != nil {
		panic(fmt.Errorf("failed to write CA cert: %w", err))
	}
	log.Println("Certificate and key received successfully.")
}
