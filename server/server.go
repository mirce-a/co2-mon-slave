package server

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/grandcat/zeroconf"
	"github.com/mirce-a/co2-mon-slave/server/handlers"
)

const (
	MasterEnrollmentURL = "http://192.168.0.165:8080/onboard" // Or discovered via mDNS
	BootstrapToken      = "123456"
	CertFile            = "slave.crt"
	KeyFile             = "slave.key"
	CACertFile          = "ca.crt"
)

type SlaveServer struct {
	CertFile       string
	KeyFile        string
	CACertFile     string
	BootstrapToken string
	Server         *http.Server
	Mux            *http.ServeMux
}

func NewSlaveServer() *SlaveServer {
	mux := http.NewServeMux()

	s := &SlaveServer{
		CACertFile:     CACertFile,
		KeyFile:        KeyFile,
		CertFile:       CertFile,
		BootstrapToken: BootstrapToken,
		Mux:            mux,
	}

	if !filesExist(CertFile, KeyFile) {
		log.Println("No certificate found. Starting enrollment...")
		s.enroll()
	}

	go broadcastService()
	s.RegisterRoutes()
	// s.StartSecureServer()

	return s
}

func filesExist(files ...string) bool {
	for _, f := range files {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func (s *SlaveServer) RegisterRoutes() {
	s.Mux = http.NewServeMux()

	s.Mux.Handle("/co2", &handlers.Co2Handler{})
	s.Mux.Handle("/co2/", &handlers.Co2Handler{})
}

func (s *SlaveServer) CreateTLSConfig() *tls.Config {
	// Load our newly minted certs
	cert, err := tls.LoadX509KeyPair(s.CertFile, s.KeyFile)
	if err != nil {
		log.Fatalf("Failed to load keypair: %v", err)
	}

	// Load CA to verify the Master's certificate
	caCert, err := os.ReadFile(s.CACertFile)
	if err != nil {
		log.Fatalf("Failed to read CA file: %v", err)
	}

	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		log.Fatal("Failed to append CA cert to pool")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert, // mTLS: Master must also show a cert
		RootCAs:      caCertPool,
	}

	return tlsConfig
}

func (s *SlaveServer) StartSecureServer() {
	tlsConfig := s.CreateTLSConfig()

	s.Server = &http.Server{
		Addr:      ":8443",
		Handler:   s.Mux,
		TLSConfig: tlsConfig,
	}

	log.Println("Secure CO2 Server listening on :8443 (mTLS)...")
	log.Fatal(s.Server.ListenAndServeTLS("", ""))
}

func (s *SlaveServer) enroll() {
	// Generate RSA Private Key
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyOut, _ := os.Create(KeyFile)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()

	// Create Certificate Signing Request (CSR)
	template := x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "slave-pi-zero-01.local"},
		DNSNames: []string{"slave-pi-zero-01.local"},
	}
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, priv)

	buf := new(bytes.Buffer)
	pem.Encode(buf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	// Send to Master (Assuming Master is at master.local)
	req, _ := http.NewRequest("POST", MasterEnrollmentURL, buf)
	req.Header.Set("Authorization", BootstrapToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		log.Fatalf("Enrollment failed: %v", err)
	}
	defer resp.Body.Close()

	// Save the signed certificate returned by Master
	certOut, _ := os.Create(s.CertFile)
	io.Copy(certOut, resp.Body)
	certOut.Sync()
	certOut.Close()
	log.Println("Enrollment successful! Certificate saved.")
}

func broadcastService() {
	server, err := zeroconf.Register(
		"CO2-Slave-01",
		"_co2-monitor._tcp",
		"local.",
		8443,
		[]string{"txtv=1"}, nil,
	)
	if err != nil {
		log.Fatalf("Failed to broadcast slave: %s", err)
	}

	defer server.Shutdown()
	select {} // Keep broadcasting
}
