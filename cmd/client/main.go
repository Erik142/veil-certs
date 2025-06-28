package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/slackhq/nebula/cert"
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

	hostname := "test-host-1"
	ipCidr := ""
	groups := []string{"test-group", "dev"}
	duration := 90 * 24 * time.Hour

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}

	req := &pb.GenerateHostCertificateRequest{
		Hostname:        hostname,
		IpCidr:          ipCidr,
		Groups:          groups,
		DurationSeconds: int64(duration.Seconds()),
		PublicKey:       pub,
	}

	log.Printf("Requesting certificate for host: %s", hostname)
	res, err := c.GenerateHostCertificate(ctx, req)
	if err != nil {
		log.Fatalf("could not generate host certificate: %v", err)
	}

	keyPEM := cert.MarshalPrivateKey(cert.Curve_CURVE25519, priv)

	fmt.Println("\n--- Generated Host Certificate (PEM) ---")
	fmt.Println(string(res.CertPem))
	fmt.Println("--- Generated Host Private Key (PEM) ---")
	fmt.Println(string(keyPEM))

	keyPath := fmt.Sprintf("%s.key", hostname)
	certPath := fmt.Sprintf("%s.crt", hostname)

	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		panic(fmt.Errorf("failed to write CA key: %w", err))
	}
	if err := os.WriteFile(certPath, res.CertPem, 0644); err != nil {
		panic(fmt.Errorf("failed to write CA cert: %w", err))
	}

	log.Println("Certificate and key received successfully.")
}

