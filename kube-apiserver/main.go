package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/core/{resource}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "resource: %v\n", vars["resource"])
	})

	r.HandleFunc("/database/{resource}", func(w http.ResponseWriter, r *http.Request) {
		dbcaPool := x509.NewCertPool()

		dbca, err := ioutil.ReadFile("../certs/db-server-ca.crt")
		if err != nil {
			log.Fatal(err)
		}

		dbcaPool.AppendCertsFromPEM(dbca)

		rhcert, err := tls.LoadX509KeyPair("../certs/rhclient.crt", "../certs/rhclient.key")
		if err != nil {
			log.Fatal(err)
		}

		client := http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					Certificates: []tls.Certificate{rhcert},
					RootCAs:      dbcaPool,
				},
			},
		}

		u := *r.URL
		u.Scheme = "https"
		u.Host = "127.0.0.2:8443"
		log.Println(u.String())

		req, err := http.NewRequest("GET", u.String(), nil)
		if err != nil {
			log.Fatal(err)
		}
		if len(r.TLS.PeerCertificates) > 0 {
			req.Header.Set("X-Remote-User", r.TLS.PeerCertificates[0].Subject.CommonName)
		}

		resp, err := client.Do(req)
		if err != nil {
			w.Write([]byte(err.Error()))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		io.Copy(w, resp.Body)
		defer resp.Body.Close()
	})

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

	server := &http.Server{Addr: "127.0.0.1:8443", Handler: r}
	server.TLSConfig = tlsConfig

	if err := server.ListenAndServeTLS("../certs/server.crt", "../certs/server.key"); err != nil {
		log.Fatal(err)
	}

}
