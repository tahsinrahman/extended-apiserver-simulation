package main

import (
	"crypto/x509"
	"fmt"
	"log"
	"net"

	"io/ioutil"

	"k8s.io/client-go/util/cert"
)

func main() {
	// generate CA that signs the api-server's tls cert
	// generate keys
	caKey, err := cert.NewPrivateKey()
	if err != nil {
		log.Fatal(err)
	}

	// generate ca cert
	caCert, err := cert.NewSelfSignedCACert(
		cert.Config{
			CommonName: "kube-apiserver-ca",
		},
		caKey,
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("ca cert")
	fmt.Println(string(cert.EncodeCertPEM(caCert)))

	if err := ioutil.WriteFile("ca-cert.crt", cert.EncodeCertPEM(caCert), 0644); err != nil {
		log.Fatal(err)
	}

	// generate api-server's tls cert
	serverKey, err := cert.NewPrivateKey()
	if err != nil {
		log.Fatal(err)
	}
	serverCert, err := cert.NewSignedCert(
		cert.Config{
			CommonName:   "kube-apiserver-tls-cert",
			Organization: []string{"kubernetes"},
			AltNames: cert.AltNames{
				DNSNames: []string{"kube-apiserver.com"},
				IPs:      []net.IP{net.ParseIP("127.0.0.1")},
			},
			Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		},
		serverKey,
		caCert,
		caKey,
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("server cert")
	fmt.Println(string(cert.EncodeCertPEM(serverCert)))

	// generate CA that signs the api-server's client certs
	// generate keys
	clientCAKey, err := cert.NewPrivateKey()
	if err != nil {
		log.Fatal(err)
	}

	// generate ca cert
	clientCACert, err := cert.NewSelfSignedCACert(
		cert.Config{
			CommonName: "kube-apiserver-client-ca",
		},
		clientCAKey,
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("client-ca cert")
	fmt.Println(string(cert.EncodeCertPEM(clientCACert)))

	// generate client certs
	clientKey, err := cert.NewPrivateKey()
	if err != nil {
		log.Fatal(err)
	}

	clientCert, err := cert.NewSignedCert(cert.Config{
		CommonName:   "admin",
		Organization: []string{"tahsin"},
		AltNames: cert.AltNames{
			DNSNames: []string{"kube-apiserver.com"},
			IPs:      []net.IP{net.ParseIP("127.0.0.1")},
		},
		Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, clientKey, clientCACert, clientCAKey)

	fmt.Println("client cert")
	fmt.Println(string(cert.EncodeCertPEM(clientCert)))
}
