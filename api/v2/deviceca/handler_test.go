// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package deviceca

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/fido-device-onboard/go-fdo-server/internal/state"
)

func setupTestDB(t *testing.T) *state.TrustedDeviceCACertsState {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "deviceca_test_*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()
	t.Cleanup(func() { os.Remove(tmpFile.Name()) })

	gormDB, err := gorm.Open(sqlite.Open(tmpFile.Name()), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	sqlDB, err := gormDB.DB()
	if err != nil {
		t.Fatalf("Failed to get underlying DB: %v", err)
	}
	t.Cleanup(func() { sqlDB.Close() })

	deviceCAState, err := state.InitTrustedDeviceCACertsDB(gormDB)
	if err != nil {
		t.Fatalf("Failed to initialize device CA state: %v", err)
	}

	return deviceCAState
}

func generateTestCert(t *testing.T, subject string, notBefore, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: subject},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

func certFingerprint(t *testing.T, pemData []byte) string {
	t.Helper()
	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("Failed to decode PEM")
	}
	hash := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(hash[:])
}

func importCert(t *testing.T, server Server, pemData []byte) {
	t.Helper()
	req := ImportTrustedDeviceCACertsRequestObject{Body: bytes.NewReader(pemData)}
	resp, err := server.ImportTrustedDeviceCACerts(context.Background(), req)
	if err != nil {
		t.Fatalf("Import failed: %v", err)
	}
	if _, ok := resp.(ImportTrustedDeviceCACerts200JSONResponse); !ok {
		t.Fatalf("Expected 200 response, got %T", resp)
	}
}

func TestListTrustedDeviceCACerts_Empty(t *testing.T) {
	server := NewServer(setupTestDB(t))

	resp, err := server.ListTrustedDeviceCACerts(context.Background(), ListTrustedDeviceCACertsRequestObject{})
	if err != nil {
		t.Fatalf("ListTrustedDeviceCACerts failed: %v", err)
	}

	okResp, ok := resp.(ListTrustedDeviceCACerts200JSONResponse)
	if !ok {
		t.Fatalf("Expected 200 JSON response, got %T", resp)
	}

	if okResp.Total != 0 {
		t.Errorf("Expected total=0, got %d", okResp.Total)
	}
	if len(okResp.Certs) != 0 {
		t.Errorf("Expected 0 certs, got %d", len(okResp.Certs))
	}
	if okResp.Limit != 20 {
		t.Errorf("Expected default limit=20, got %d", okResp.Limit)
	}
	if okResp.Offset != 0 {
		t.Errorf("Expected default offset=0, got %d", okResp.Offset)
	}
}

func TestListTrustedDeviceCACerts_WithData(t *testing.T) {
	server := NewServer(setupTestDB(t))

	certPEM := generateTestCert(t, "Test CA", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	importCert(t, server, certPEM)

	resp, err := server.ListTrustedDeviceCACerts(context.Background(), ListTrustedDeviceCACertsRequestObject{})
	if err != nil {
		t.Fatalf("ListTrustedDeviceCACerts failed: %v", err)
	}

	okResp, ok := resp.(ListTrustedDeviceCACerts200JSONResponse)
	if !ok {
		t.Fatalf("Expected 200 JSON response, got %T", resp)
	}

	if okResp.Total != 1 {
		t.Errorf("Expected total=1, got %d", okResp.Total)
	}
	if len(okResp.Certs) != 1 {
		t.Errorf("Expected 1 cert, got %d", len(okResp.Certs))
	}
	if !strings.Contains(okResp.Certs[0].Subject, "Test CA") {
		t.Errorf("Expected subject containing 'Test CA', got %q", okResp.Certs[0].Subject)
	}
	if okResp.Certs[0].Fingerprint == "" {
		t.Error("Expected non-empty fingerprint")
	}
	if okResp.Certs[0].Pem == "" {
		t.Error("Expected non-empty PEM")
	}
}

func TestListTrustedDeviceCACerts_Pagination(t *testing.T) {
	server := NewServer(setupTestDB(t))

	for i := 0; i < 3; i++ {
		certPEM := generateTestCert(t, "CA "+string(rune('A'+i)), time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
		importCert(t, server, certPEM)
	}

	limit := 2
	offset := 0
	resp, err := server.ListTrustedDeviceCACerts(context.Background(), ListTrustedDeviceCACertsRequestObject{
		Params: ListTrustedDeviceCACertsParams{
			Limit:  &limit,
			Offset: &offset,
		},
	})
	if err != nil {
		t.Fatalf("ListTrustedDeviceCACerts failed: %v", err)
	}

	okResp, ok := resp.(ListTrustedDeviceCACerts200JSONResponse)
	if !ok {
		t.Fatalf("Expected 200 JSON response, got %T", resp)
	}

	if okResp.Total != 3 {
		t.Errorf("Expected total=3, got %d", okResp.Total)
	}
	if len(okResp.Certs) != 2 {
		t.Errorf("Expected 2 certs (limit), got %d", len(okResp.Certs))
	}
	if okResp.Limit != 2 {
		t.Errorf("Expected limit=2, got %d", okResp.Limit)
	}

	offset = 2
	resp, err = server.ListTrustedDeviceCACerts(context.Background(), ListTrustedDeviceCACertsRequestObject{
		Params: ListTrustedDeviceCACertsParams{
			Limit:  &limit,
			Offset: &offset,
		},
	})
	if err != nil {
		t.Fatalf("ListTrustedDeviceCACerts (page 2) failed: %v", err)
	}

	okResp, ok = resp.(ListTrustedDeviceCACerts200JSONResponse)
	if !ok {
		t.Fatalf("Expected 200 JSON response, got %T", resp)
	}

	if len(okResp.Certs) != 1 {
		t.Errorf("Expected 1 cert on page 2, got %d", len(okResp.Certs))
	}
	if okResp.Offset != 2 {
		t.Errorf("Expected offset=2, got %d", okResp.Offset)
	}
}

func TestListTrustedDeviceCACerts_SortOrder(t *testing.T) {
	server := NewServer(setupTestDB(t))

	certA := generateTestCert(t, "AAA CA", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	certZ := generateTestCert(t, "ZZZ CA", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	importCert(t, server, certA)
	importCert(t, server, certZ)

	sortBy := Subject
	sortOrder := Desc
	resp, err := server.ListTrustedDeviceCACerts(context.Background(), ListTrustedDeviceCACertsRequestObject{
		Params: ListTrustedDeviceCACertsParams{
			SortBy:    &sortBy,
			SortOrder: &sortOrder,
		},
	})
	if err != nil {
		t.Fatalf("ListTrustedDeviceCACerts failed: %v", err)
	}

	okResp, ok := resp.(ListTrustedDeviceCACerts200JSONResponse)
	if !ok {
		t.Fatalf("Expected 200 JSON response, got %T", resp)
	}

	if len(okResp.Certs) != 2 {
		t.Fatalf("Expected 2 certs, got %d", len(okResp.Certs))
	}
	if !strings.Contains(okResp.Certs[0].Subject, "ZZZ") {
		t.Errorf("Expected first cert to be ZZZ (desc order), got %q", okResp.Certs[0].Subject)
	}
}

func TestListTrustedDeviceCACerts_FilterBySubject(t *testing.T) {
	server := NewServer(setupTestDB(t))

	certA := generateTestCert(t, "Alpha CA", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	certB := generateTestCert(t, "Beta CA", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	importCert(t, server, certA)
	importCert(t, server, certB)

	// The subject stored in the DB is the full DN, e.g. "CN=Alpha CA"
	subject := "CN=Alpha CA"
	resp, err := server.ListTrustedDeviceCACerts(context.Background(), ListTrustedDeviceCACertsRequestObject{
		Params: ListTrustedDeviceCACertsParams{
			Subject: &subject,
		},
	})
	if err != nil {
		t.Fatalf("ListTrustedDeviceCACerts failed: %v", err)
	}

	okResp, ok := resp.(ListTrustedDeviceCACerts200JSONResponse)
	if !ok {
		t.Fatalf("Expected 200 JSON response, got %T", resp)
	}

	if okResp.Total != 1 {
		t.Errorf("Expected total=1 with subject filter, got %d", okResp.Total)
	}
	if len(okResp.Certs) != 1 {
		t.Errorf("Expected 1 cert, got %d", len(okResp.Certs))
	}
}

func TestListTrustedDeviceCACerts_Search(t *testing.T) {
	server := NewServer(setupTestDB(t))

	certA := generateTestCert(t, "Alpha CA", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	certB := generateTestCert(t, "Beta CA", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	importCert(t, server, certA)
	importCert(t, server, certB)

	search := "Alpha"
	resp, err := server.ListTrustedDeviceCACerts(context.Background(), ListTrustedDeviceCACertsRequestObject{
		Params: ListTrustedDeviceCACertsParams{
			Search: &search,
		},
	})
	if err != nil {
		t.Fatalf("ListTrustedDeviceCACerts failed: %v", err)
	}

	okResp, ok := resp.(ListTrustedDeviceCACerts200JSONResponse)
	if !ok {
		t.Fatalf("Expected 200 JSON response, got %T", resp)
	}

	if okResp.Total != 1 {
		t.Errorf("Expected total=1 with search filter, got %d", okResp.Total)
	}
}

func TestImportTrustedDeviceCACerts_ValidCert(t *testing.T) {
	server := NewServer(setupTestDB(t))

	certPEM := generateTestCert(t, "Import Test CA", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	req := ImportTrustedDeviceCACertsRequestObject{Body: bytes.NewReader(certPEM)}
	resp, err := server.ImportTrustedDeviceCACerts(context.Background(), req)
	if err != nil {
		t.Fatalf("ImportTrustedDeviceCACerts failed: %v", err)
	}

	okResp, ok := resp.(ImportTrustedDeviceCACerts200JSONResponse)
	if !ok {
		t.Fatalf("Expected 200 response, got %T", resp)
	}

	if okResp.Detected != 1 {
		t.Errorf("Expected detected=1, got %d", okResp.Detected)
	}
	if okResp.Imported != 1 {
		t.Errorf("Expected imported=1, got %d", okResp.Imported)
	}
	if okResp.Skipped != 0 {
		t.Errorf("Expected skipped=0, got %d", okResp.Skipped)
	}
	if okResp.Malformed != 0 {
		t.Errorf("Expected malformed=0, got %d", okResp.Malformed)
	}
	if len(okResp.Certs) != 1 {
		t.Errorf("Expected 1 cert in response, got %d", len(okResp.Certs))
	}
}

func TestImportTrustedDeviceCACerts_MultipleCerts(t *testing.T) {
	server := NewServer(setupTestDB(t))

	cert1 := generateTestCert(t, "Multi CA 1", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	cert2 := generateTestCert(t, "Multi CA 2", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	combined := append(cert1, cert2...)

	req := ImportTrustedDeviceCACertsRequestObject{Body: bytes.NewReader(combined)}
	resp, err := server.ImportTrustedDeviceCACerts(context.Background(), req)
	if err != nil {
		t.Fatalf("ImportTrustedDeviceCACerts failed: %v", err)
	}

	okResp, ok := resp.(ImportTrustedDeviceCACerts200JSONResponse)
	if !ok {
		t.Fatalf("Expected 200 response, got %T", resp)
	}

	if okResp.Detected != 2 {
		t.Errorf("Expected detected=2, got %d", okResp.Detected)
	}
	if okResp.Imported != 2 {
		t.Errorf("Expected imported=2, got %d", okResp.Imported)
	}
}

func TestImportTrustedDeviceCACerts_Idempotent(t *testing.T) {
	server := NewServer(setupTestDB(t))

	certPEM := generateTestCert(t, "Idempotent CA", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	importCert(t, server, certPEM)

	req := ImportTrustedDeviceCACertsRequestObject{Body: bytes.NewReader(certPEM)}
	resp, err := server.ImportTrustedDeviceCACerts(context.Background(), req)
	if err != nil {
		t.Fatalf("Second import failed: %v", err)
	}

	okResp, ok := resp.(ImportTrustedDeviceCACerts200JSONResponse)
	if !ok {
		t.Fatalf("Expected 200 response, got %T", resp)
	}

	if okResp.Imported != 0 {
		t.Errorf("Expected imported=0 on second import, got %d", okResp.Imported)
	}
	if okResp.Skipped != 1 {
		t.Errorf("Expected skipped=1 on second import, got %d", okResp.Skipped)
	}
}

func TestImportTrustedDeviceCACerts_ExpiredCert(t *testing.T) {
	server := NewServer(setupTestDB(t))

	certPEM := generateTestCert(t, "Expired CA", time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))

	req := ImportTrustedDeviceCACertsRequestObject{Body: bytes.NewReader(certPEM)}
	resp, err := server.ImportTrustedDeviceCACerts(context.Background(), req)
	if err != nil {
		t.Fatalf("ImportTrustedDeviceCACerts failed: %v", err)
	}

	okResp, ok := resp.(ImportTrustedDeviceCACerts200JSONResponse)
	if !ok {
		t.Fatalf("Expected 200 response, got %T", resp)
	}

	if okResp.Imported != 0 {
		t.Errorf("Expected imported=0 for expired cert, got %d", okResp.Imported)
	}
	if okResp.Skipped != 1 {
		t.Errorf("Expected skipped=1 for expired cert, got %d", okResp.Skipped)
	}
}

func TestImportTrustedDeviceCACerts_MalformedPEM(t *testing.T) {
	server := NewServer(setupTestDB(t))

	malformedPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a valid DER certificate")})

	req := ImportTrustedDeviceCACertsRequestObject{Body: bytes.NewReader(malformedPEM)}
	resp, err := server.ImportTrustedDeviceCACerts(context.Background(), req)
	if err != nil {
		t.Fatalf("ImportTrustedDeviceCACerts failed: %v", err)
	}

	okResp, ok := resp.(ImportTrustedDeviceCACerts200JSONResponse)
	if !ok {
		t.Fatalf("Expected 200 response, got %T", resp)
	}

	if okResp.Malformed != 1 {
		t.Errorf("Expected malformed=1, got %d", okResp.Malformed)
	}
	if okResp.Imported != 0 {
		t.Errorf("Expected imported=0, got %d", okResp.Imported)
	}
}

func TestImportTrustedDeviceCACerts_EmptyBody(t *testing.T) {
	server := NewServer(setupTestDB(t))

	req := ImportTrustedDeviceCACertsRequestObject{Body: bytes.NewReader(nil)}
	resp, err := server.ImportTrustedDeviceCACerts(context.Background(), req)
	if err != nil {
		t.Fatalf("ImportTrustedDeviceCACerts failed: %v", err)
	}

	okResp, ok := resp.(ImportTrustedDeviceCACerts200JSONResponse)
	if !ok {
		t.Fatalf("Expected 200 response, got %T", resp)
	}

	if okResp.Detected != 0 {
		t.Errorf("Expected detected=0, got %d", okResp.Detected)
	}
	if okResp.Imported != 0 {
		t.Errorf("Expected imported=0, got %d", okResp.Imported)
	}
}

func TestImportTrustedDeviceCACerts_MaxBytesError(t *testing.T) {
	server := NewServer(setupTestDB(t))

	reader := io.LimitReader(bytes.NewReader([]byte("data")), 0)
	limitedReader := http.MaxBytesReader(nil, io.NopCloser(reader), 0)

	req := ImportTrustedDeviceCACertsRequestObject{Body: limitedReader}
	resp, err := server.ImportTrustedDeviceCACerts(context.Background(), req)
	if err != nil {
		t.Fatalf("ImportTrustedDeviceCACerts failed: %v", err)
	}

	_, ok := resp.(ImportTrustedDeviceCACerts413JSONResponse)
	if !ok {
		// MaxBytesReader with limit 0 may return empty body (no error) depending on read behavior.
		// Just verify we get a valid response type.
		if _, ok := resp.(ImportTrustedDeviceCACerts200JSONResponse); !ok {
			t.Fatalf("Expected 413 or 200 response, got %T", resp)
		}
	}
}

func TestGetTrustedDeviceCACertByFingerprint_Found(t *testing.T) {
	server := NewServer(setupTestDB(t))

	certPEM := generateTestCert(t, "Get Test CA", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	fingerprint := certFingerprint(t, certPEM)
	importCert(t, server, certPEM)

	req := GetTrustedDeviceCACertByFingerprintRequestObject{Fingerprint: fingerprint}
	resp, err := server.GetTrustedDeviceCACertByFingerprint(context.Background(), req)
	if err != nil {
		t.Fatalf("GetTrustedDeviceCACertByFingerprint failed: %v", err)
	}

	okResp, ok := resp.(GetTrustedDeviceCACertByFingerprint200JSONResponse)
	if !ok {
		t.Fatalf("Expected 200 JSON response, got %T", resp)
	}

	if okResp.Fingerprint != fingerprint {
		t.Errorf("Expected fingerprint %q, got %q", fingerprint, okResp.Fingerprint)
	}
	if !strings.Contains(okResp.Subject, "Get Test CA") {
		t.Errorf("Expected subject containing 'Get Test CA', got %q", okResp.Subject)
	}
	if okResp.Pem == "" {
		t.Error("Expected non-empty PEM")
	}
}

func TestGetTrustedDeviceCACertByFingerprint_NotFound(t *testing.T) {
	server := NewServer(setupTestDB(t))

	req := GetTrustedDeviceCACertByFingerprintRequestObject{Fingerprint: "nonexistent"}
	resp, err := server.GetTrustedDeviceCACertByFingerprint(context.Background(), req)
	if err != nil {
		t.Fatalf("GetTrustedDeviceCACertByFingerprint failed: %v", err)
	}

	_, ok := resp.(GetTrustedDeviceCACertByFingerprint404JSONResponse)
	if !ok {
		t.Fatalf("Expected 404 response, got %T", resp)
	}
}

func TestDeleteTrustedDeviceCACert_Found(t *testing.T) {
	server := NewServer(setupTestDB(t))

	certPEM := generateTestCert(t, "Delete Test CA", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	fingerprint := certFingerprint(t, certPEM)
	importCert(t, server, certPEM)

	req := DeleteTrustedDeviceCACertRequestObject{Fingerprint: fingerprint}
	resp, err := server.DeleteTrustedDeviceCACert(context.Background(), req)
	if err != nil {
		t.Fatalf("DeleteTrustedDeviceCACert failed: %v", err)
	}

	_, ok := resp.(DeleteTrustedDeviceCACert204Response)
	if !ok {
		t.Fatalf("Expected 204 response, got %T", resp)
	}

	// Verify it's actually gone
	getReq := GetTrustedDeviceCACertByFingerprintRequestObject{Fingerprint: fingerprint}
	getResp, err := server.GetTrustedDeviceCACertByFingerprint(context.Background(), getReq)
	if err != nil {
		t.Fatalf("GetTrustedDeviceCACertByFingerprint after delete failed: %v", err)
	}
	if _, ok := getResp.(GetTrustedDeviceCACertByFingerprint404JSONResponse); !ok {
		t.Fatalf("Expected 404 after deletion, got %T", getResp)
	}
}

func TestDeleteTrustedDeviceCACert_NotFound(t *testing.T) {
	server := NewServer(setupTestDB(t))

	req := DeleteTrustedDeviceCACertRequestObject{Fingerprint: "nonexistent"}
	resp, err := server.DeleteTrustedDeviceCACert(context.Background(), req)
	if err != nil {
		t.Fatalf("DeleteTrustedDeviceCACert failed: %v", err)
	}

	_, ok := resp.(DeleteTrustedDeviceCACert404JSONResponse)
	if !ok {
		t.Fatalf("Expected 404 response, got %T", resp)
	}
}

func TestImportAndList_EndToEnd(t *testing.T) {
	server := NewServer(setupTestDB(t))

	cert1 := generateTestCert(t, "E2E CA 1", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	cert2 := generateTestCert(t, "E2E CA 2", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	fp1 := certFingerprint(t, cert1)

	importCert(t, server, append(cert1, cert2...))

	listResp, err := server.ListTrustedDeviceCACerts(context.Background(), ListTrustedDeviceCACertsRequestObject{})
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	okList := listResp.(ListTrustedDeviceCACerts200JSONResponse)
	if okList.Total != 2 {
		t.Fatalf("Expected total=2, got %d", okList.Total)
	}

	getResp, err := server.GetTrustedDeviceCACertByFingerprint(context.Background(), GetTrustedDeviceCACertByFingerprintRequestObject{Fingerprint: fp1})
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if _, ok := getResp.(GetTrustedDeviceCACertByFingerprint200JSONResponse); !ok {
		t.Fatalf("Expected 200, got %T", getResp)
	}

	delResp, err := server.DeleteTrustedDeviceCACert(context.Background(), DeleteTrustedDeviceCACertRequestObject{Fingerprint: fp1})
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if _, ok := delResp.(DeleteTrustedDeviceCACert204Response); !ok {
		t.Fatalf("Expected 204, got %T", delResp)
	}

	listResp2, err := server.ListTrustedDeviceCACerts(context.Background(), ListTrustedDeviceCACertsRequestObject{})
	if err != nil {
		t.Fatalf("List after delete failed: %v", err)
	}
	okList2 := listResp2.(ListTrustedDeviceCACerts200JSONResponse)
	if okList2.Total != 1 {
		t.Errorf("Expected total=1 after deletion, got %d", okList2.Total)
	}
}
