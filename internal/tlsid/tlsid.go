// Package tlsid is Sund's TLS identity: a two-layer certificate model plus the
// client-side fingerprint pinning that makes first-connect MITM detectable
// without a public CA (PRD, Server address).
//
// A long-lived offline CA is the stable identity; clients pin the SHA-256 of its
// SubjectPublicKeyInfo, delivered out-of-band in the sund:// address. The CA
// signs a shorter-lived online (leaf) certificate used for the live TLS
// handshake — so the server can rotate the leaf without changing the pin. On
// disk: ca.crt / ca.key (stable) and server.crt / server.key (regenerate to
// rotate). The offline key living beside the server is a pragmatic compromise
// for self-hosting; the design keeps the pin stable regardless.
package tlsid

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	caValidity   = 10 * 365 * 24 * time.Hour // long-lived, stable identity
	leafValidity = 397 * 24 * time.Hour      // rotatable online cert
)

// Identity is the loaded certificate material plus the pinned fingerprint.
type Identity struct {
	ca          *x509.Certificate
	serverChain tls.Certificate
	// Fingerprint is the hex SHA-256 of the CA's SubjectPublicKeyInfo — the
	// value clients pin and that goes in the sund:// address.
	Fingerprint string
}

// Load loads the identity from dir, generating whatever is missing. The CA (and
// therefore the fingerprint) is stable across restarts; the leaf is regenerated
// when absent, so deleting server.crt/server.key rotates it without changing the
// pin.
func Load(dir string) (*Identity, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	caCertPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")
	leafCertPath := filepath.Join(dir, "server.crt")
	leafKeyPath := filepath.Join(dir, "server.key")

	ca, caKey, err := loadOrCreateCA(caCertPath, caKeyPath)
	if err != nil {
		return nil, fmt.Errorf("ca: %w", err)
	}
	chain, err := loadOrCreateLeaf(leafCertPath, leafKeyPath, ca, caKey)
	if err != nil {
		return nil, fmt.Errorf("leaf: %w", err)
	}
	return &Identity{ca: ca, serverChain: chain, Fingerprint: SPKIFingerprint(ca)}, nil
}

// ServerTLSConfig returns a config presenting the chain [leaf, CA].
func (id *Identity) ServerTLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{id.serverChain},
		MinVersion:   tls.VersionTLS12,
	}
}

// ClientTLSConfig returns a config that accepts a connection only if the
// presented chain contains a certificate whose SPKI SHA-256 equals fingerprint
// and the leaf validly chains to it. Default WebPKI verification is bypassed —
// identity is the pinned key, not a CA or hostname.
func ClientTLSConfig(fingerprint string) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, // replaced by the pin check below
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyPinned(rawCerts, fingerprint)
		},
		MinVersion: tls.VersionTLS12,
	}
}

// SPKIFingerprint is the hex SHA-256 of a certificate's SubjectPublicKeyInfo.
func SPKIFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

func verifyPinned(rawCerts [][]byte, fingerprint string) error {
	if len(rawCerts) == 0 {
		return errors.New("tls: server presented no certificate")
	}
	certs := make([]*x509.Certificate, 0, len(rawCerts))
	for _, raw := range rawCerts {
		c, err := x509.ParseCertificate(raw)
		if err != nil {
			return err
		}
		certs = append(certs, c)
	}

	var pinned *x509.Certificate
	for _, c := range certs {
		if SPKIFingerprint(c) == fingerprint {
			pinned = c
			break
		}
	}
	if pinned == nil {
		return errors.New("tls: server certificate does not match the pinned fingerprint")
	}

	roots := x509.NewCertPool()
	roots.AddCert(pinned)
	inters := x509.NewCertPool()
	for _, c := range certs[1:] {
		inters.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err
}

func loadOrCreateCA(certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if fileExists(certPath) && fileExists(keyPath) {
		cert, err := readCert(certPath)
		if err != nil {
			return nil, nil, err
		}
		key, err := readKey(keyPath)
		if err != nil {
			return nil, nil, err
		}
		return cert, key, nil
	}
	return createCA(certPath, keyPath)
}

func createCA(certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          randSerial(),
		Subject:               pkix.Name{CommonName: "Sund Offline CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	if err := writeCertPEM(certPath, der); err != nil {
		return nil, nil, err
	}
	if err := writeKeyPEM(keyPath, key); err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func loadOrCreateLeaf(certPath, keyPath string, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (tls.Certificate, error) {
	if fileExists(certPath) && fileExists(keyPath) {
		if chain, err := loadLeaf(certPath, keyPath, ca); err == nil {
			return chain, nil
		}
		// Any problem (expired, wrong CA, unreadable) → regenerate.
	}
	return createLeaf(certPath, keyPath, ca, caKey)
}

func loadLeaf(certPath, keyPath string, ca *x509.Certificate) (tls.Certificate, error) {
	leaf, err := readCert(certPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	key, err := readKey(keyPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := leaf.CheckSignatureFrom(ca); err != nil {
		return tls.Certificate{}, err
	}
	if time.Now().After(leaf.NotAfter) {
		return tls.Certificate{}, errors.New("leaf certificate expired")
	}
	return tls.Certificate{Certificate: [][]byte{leaf.Raw, ca.Raw}, PrivateKey: key, Leaf: leaf}, nil
}

func createLeaf(certPath, keyPath string, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: randSerial(),
		Subject:      pkix.Name{CommonName: "Sund"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(leafValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := writeCertPEM(certPath, der); err != nil {
		return tls.Certificate{}, err
	}
	if err := writeKeyPEM(keyPath, key); err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key, Leaf: leaf}, nil
}

func readCert(path string) (*x509.Certificate, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM certificate in %s", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

func readKey(path string) (*ecdsa.PrivateKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM key in %s", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("key is not ECDSA")
	}
	return ec, nil
}

func writeCertPEM(path string, der []byte) error {
	return writePEM(path, "CERTIFICATE", der, 0o644)
}

func writeKeyPEM(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return writePEM(path, "PRIVATE KEY", der, 0o600)
}

func writePEM(path, typ string, der []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: typ, Bytes: der})
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func randSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	return n
}
