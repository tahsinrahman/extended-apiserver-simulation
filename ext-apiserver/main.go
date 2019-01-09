package main

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	caCertPool := x509.NewCertPool()
	cert, err := ioutil.ReadFile("../certs/rhclient-ca.crt")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool.AppendCertsFromPEM(cert)

	tlsConfig := &tls.Config{
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
		SessionTicketsDisabled:   true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, // Go 1.8 only
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,   // Go 1.8 only
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		ClientAuth: tls.VerifyClientCertIfGiven,
		NextProtos: []string{"h2", "http/1.1"},
	}

	tlsConfig.ClientCAs = caCertPool
	tlsConfig.BuildNameToCertificate()

	r := mux.NewRouter()
	r.HandleFunc("/database/{dbtype}", func(w http.ResponseWriter, r *http.Request) {
		user := "system:anonymous"
		if _, err := r.TLS.PeerCertificates[0].Verify(
			x509.VerifyOptions{
				Roots:     caCertPool,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			},
		); err != nil {
			w.Write([]byte(err.Error()))
		} else {
			user = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		w.Write([]byte(user))
	})

	server := &http.Server{Addr: "127.0.0.2:8443", Handler: r}
	server.TLSConfig = tlsConfig

	if err := server.ListenAndServeTLS("../certs/db-server.crt", "../certs/db-server.key"); err != nil {
		log.Fatal(err)
	}
}
