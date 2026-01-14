// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package deviceca

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/fido-device-onboard/go-fdo-server/internal/db"
	"github.com/fido-device-onboard/go-fdo-server/internal/handlers/components"
	"gorm.io/gorm"
)

// Server implements the ServerInterface for device CA certificate management
type Server struct {
	State *db.State
}

func NewServer(state *db.State) Server {
	return Server{State: state}
}

var _ StrictServerInterface = (*Server)(nil)

// ListTrustedDeviceCACerts lists all trusted device CA certificates with pagination, filtering, and sorting
func (s *Server) ListTrustedDeviceCACerts(ctx context.Context, request ListTrustedDeviceCACertsRequestObject) (ListTrustedDeviceCACertsResponseObject, error) {
	// Set defaults
	limit := 20
	if request.Params.Limit != nil {
		limit = *request.Params.Limit
	}

	offset := 0
	if request.Params.Offset != nil {
		offset = *request.Params.Offset
	}

	sortBy := "created_at"
	if request.Params.SortBy != nil {
		switch *request.Params.SortBy {
		case CreatedAt:
			sortBy = "created_at"
		case NotAfter:
			sortBy = "not_after"
		case NotBefore:
			sortBy = "not_before"
		case Subject:
			sortBy = "subject"
		case Issuer:
			sortBy = "issuer"
		}
	}

	sortOrder := "asc"
	if request.Params.SortOrder != nil {
		sortOrder = string(*request.Params.SortOrder)
	}

	// Call the database layer with all filters
	certs, total, err := s.State.ListDeviceCACertificates(ctx, limit, offset, request.Params.Issuer, request.Params.Subject, request.Params.Search, sortBy, sortOrder)
	if err != nil {
		slog.Error("Failed to list device CA certificates", "error", err)
		return ListTrustedDeviceCACerts500JSONResponse{
			InternalServerError: components.InternalServerError{
				Message: "Failed to list device CA certificates",
			},
		}, nil
	}

	// Apply validity status filter if specified (in-memory filtering)
	if request.Params.ValidityStatus != nil {
		certs = filterByValidityStatus(certs, *request.Params.ValidityStatus)
		total = int64(len(certs))
	}

	// Convert to response format
	data := make([]TrustedDeviceCACert, len(certs))
	for i, cert := range certs {
		data[i] = TrustedDeviceCACert{
			Fingerprint: cert.Fingerprint,
			Pem:         cert.PEM,
			Subject:     cert.Subject,
			Issuer:      cert.Issuer,
			NotBefore:   cert.NotBefore,
			NotAfter:    cert.NotAfter,
			CreatedAt:   cert.CreatedAt,
		}
	}

	return ListTrustedDeviceCACerts200JSONResponse(TrustedDeviceCACertsPaginated{
		Total:  int(total),
		Limit:  limit,
		Offset: offset,
		Certs:  data,
	}), nil
}

// CreateTrustedDeviceCACerts creates one or more trusted device CA certificates (idempotent)
func (s *Server) CreateTrustedDeviceCACerts(ctx context.Context, request CreateTrustedDeviceCACertsRequestObject) (CreateTrustedDeviceCACertsResponseObject, error) {
	// Read the PEM data from the request body with size limit (1MB)
	const maxSize = 1048576 // 1MB
	pemData, err := io.ReadAll(io.LimitReader(request.Body, maxSize+1))
	if err != nil {
		slog.Error("Failed to read request body", "error", err)
		return CreateTrustedDeviceCACerts400JSONResponse{
			BadRequest: components.BadRequest{
				Message: "Failed to read request body",
			},
		}, nil
	}

	// Check payload size
	if len(pemData) > maxSize {
		slog.Warn("Request payload too large", "size", len(pemData), "max", maxSize)
		return CreateTrustedDeviceCACerts413JSONResponse(components.Error{
			Message: fmt.Sprintf("Request payload exceeds maximum size of %d bytes", maxSize),
		}), nil
	}

	// Import the certificates using the idempotent method
	stats, err := s.State.ImportDeviceCACertificates(ctx, string(pemData))
	if err != nil {
		slog.Error("Failed to import device CA certificates", "error", err)
		return CreateTrustedDeviceCACerts500JSONResponse{
			InternalServerError: components.InternalServerError{
				Message: "Failed to import certificates",
			},
		}, nil
	}

	// Reload the trusted device CA cert pool if any certificates were imported
	if stats.Imported > 0 {
		if err := s.State.LoadTrustedDeviceCAs(ctx); err != nil {
			slog.Error("Failed to reload trusted device CA cert pool", "error", err)
			return CreateTrustedDeviceCACerts500JSONResponse{
				InternalServerError: components.InternalServerError{
					Message: "Failed to reload trusted device CA certificates",
				},
			}, nil
		}
		slog.Info("Reloaded trusted device CA cert pool", "imported", stats.Imported)
	}

	// Convert imported certificates to response format
	certificates := make([]TrustedDeviceCACert, len(stats.Certificates))
	for i, cert := range stats.Certificates {
		certificates[i] = TrustedDeviceCACert{
			Fingerprint: cert.Fingerprint,
			Pem:         cert.PEM,
			Subject:     cert.Subject,
			Issuer:      cert.Issuer,
			NotBefore:   cert.NotBefore,
			NotAfter:    cert.NotAfter,
			CreatedAt:   cert.CreatedAt,
		}
	}

	return CreateTrustedDeviceCACerts200JSONResponse(TrustedDeviceCACertsImportResult{
		Detected:  stats.Detected,
		Imported:  stats.Imported,
		Skipped:   stats.Skipped,
		Malformed: stats.Malformed,
		Certs:     certificates,
	}), nil
}

// GetTrustedDeviceCACertByFingerprint retrieves a device CA certificate by fingerprint
func (s *Server) GetTrustedDeviceCACertByFingerprint(ctx context.Context, request GetTrustedDeviceCACertByFingerprintRequestObject) (GetTrustedDeviceCACertByFingerprintResponseObject, error) {
	cert, err := s.State.GetDeviceCACertificate(ctx, request.Fingerprint)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) || err.Error() == "device CA certificate not found" {
			slog.Debug("Device CA certificate not found", "fingerprint", request.Fingerprint)
			return GetTrustedDeviceCACertByFingerprint404JSONResponse{
				NotFound: components.NotFound{
					Message: "Device CA certificate not found",
				},
			}, nil
		}
		slog.Error("Failed to get device CA certificate", "error", err, "fingerprint", request.Fingerprint)
		return GetTrustedDeviceCACertByFingerprint500JSONResponse{
			InternalServerError: components.InternalServerError{
				Message: "Failed to retrieve certificate",
			},
		}, nil
	}

	// Return the PEM data
	pemReader := bytes.NewReader([]byte(cert.PEM))
	return GetTrustedDeviceCACertByFingerprint200ApplicationxPemFileResponse{
		Body:          pemReader,
		ContentLength: int64(len(cert.PEM)),
	}, nil
}

// DeleteTrustedDeviceCACert deletes a device CA certificate by fingerprint
func (s *Server) DeleteTrustedDeviceCACert(ctx context.Context, request DeleteTrustedDeviceCACertRequestObject) (DeleteTrustedDeviceCACertResponseObject, error) {
	err := s.State.DeleteDeviceCACertificate(ctx, request.Fingerprint)
	if err != nil {
		if err.Error() == "device CA certificate not found" {
			slog.Debug("Device CA certificate not found", "fingerprint", request.Fingerprint)
			return DeleteTrustedDeviceCACert404JSONResponse{
				NotFound: components.NotFound{
					Message: "Device CA certificate not found",
				},
			}, nil
		}
		slog.Error("Failed to delete device CA certificate", "error", err, "fingerprint", request.Fingerprint)
		return DeleteTrustedDeviceCACert500JSONResponse{
			InternalServerError: components.InternalServerError{
				Message: "Failed to delete certificate",
			},
		}, nil
	}

	// Reload the trusted device CA cert pool after deletion
	if err := s.State.LoadTrustedDeviceCAs(ctx); err != nil {
		slog.Error("Failed to reload trusted device CA cert pool", "error", err)
		return DeleteTrustedDeviceCACert500JSONResponse{
			InternalServerError: components.InternalServerError{
				Message: "Failed to reload trusted device CA certificates",
			},
		}, nil
	}
	slog.Info("Reloaded trusted device CA cert pool after deletion", "fingerprint", request.Fingerprint)

	return DeleteTrustedDeviceCACert204Response{}, nil
}

// filterByValidityStatus filters certificates based on their validity status
func filterByValidityStatus(certs []db.DeviceCACertificate, status ListTrustedDeviceCACertsParamsValidityStatus) []db.DeviceCACertificate {
	now := time.Now()
	filtered := make([]db.DeviceCACertificate, 0, len(certs))

	for _, cert := range certs {
		switch status {
		case Valid:
			if now.After(cert.NotBefore) && now.Before(cert.NotAfter) {
				filtered = append(filtered, cert)
			}
		case Expired:
			if now.After(cert.NotAfter) {
				filtered = append(filtered, cert)
			}
		case NotYetValid:
			if now.Before(cert.NotBefore) {
				filtered = append(filtered, cert)
			}
		}
	}

	return filtered
}
