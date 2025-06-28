package server

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Erik142/veil-certs/pkg/castore"
	"github.com/Erik142/veil-certs/pkg/certgen"
	"github.com/Erik142/veil-certs/pkg/keyprovider"
	pb "github.com/Erik142/veil-certs/pkg/proto"
)

// CertificateServiceServer implements the gRPC service for certificate generation.
type CertificateServiceServer struct {
	pb.UnimplementedCertificateServiceServer // Required for forward compatibility
	CAStore                                  castore.CAStore
	PassphraseProvider                       keyprovider.KeyPassphraseProvider
	Generator                                certgen.CertificateGenerator
	log                                      *logrus.Entry
}

// NewCertificateServiceServer creates a new CertificateServiceServer instance.
func NewCertificateServiceServer(caStore castore.CAStore, passphraseProvider keyprovider.KeyPassphraseProvider, generator certgen.CertificateGenerator) *CertificateServiceServer {
	return &CertificateServiceServer{
		CAStore:            caStore,
		PassphraseProvider: passphraseProvider,
		Generator:          generator,
		log:                logrus.WithField("component", "CertificateServiceServer"),
	}
}

// GenerateHostCertificate handles the gRPC request to generate a host certificate.
func (s *CertificateServiceServer) GenerateHostCertificate(ctx context.Context, req *pb.GenerateHostCertificateRequest) (*pb.GenerateHostCertificateResponse, error) {
	s.log.WithFields(logrus.Fields{
		"hostname": req.Hostname,
		"ip_cidr":  req.IpCidr,
		"groups":   req.Groups,
		"duration": req.DurationSeconds,
	}).Info("Received request to generate host certificate.")

	caCertPEM, caKeyPEM, err := s.CAStore.LoadCA()
	if err != nil {
		s.log.WithError(err).Error("Failed to load CA certificate and key.")
		return nil, status.Errorf(codes.Unavailable, "failed to load CA: %v", err)
	}

	duration := time.Duration(req.DurationSeconds) * time.Second
	if duration <= 0 {
		s.log.Warn("Invalid duration_seconds provided. Using default (90 days).")
		duration = 90 * 24 * time.Hour // Default to 90 days if invalid
	}

	certPEM, err := s.Generator.GenerateHostCertificateFromPublicKey(caCertPEM, caKeyPEM, s.PassphraseProvider, req.Hostname, req.IpCidr, req.Groups, duration, req.PublicKey)
	if err != nil {
		s.log.WithError(err).Error("Failed to generate host certificate.")
		return nil, status.Errorf(codes.Internal, "failed to generate host certificate: %v", err)
	}

	s.log.Info("Successfully generated host certificate.")
	return &pb.GenerateHostCertificateResponse{
		CertPem: certPEM,
	}, nil
}
