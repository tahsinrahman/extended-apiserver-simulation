package main

import (
	"crypto/x509"
	"log"
	"net"

	"github.com/tahsinrahman/extended-apiserver-simulation/certStore"
	"k8s.io/client-go/util/cert"
)

/*
[x] server-ca
[x] server-certs

[x] rh-client-ca
[x] rh-client-certs

[x] db-server-ca
[x] db-server-certs
*/

func main() {
	// generate CA that signs the api-server's tls cert
	tlsStore, err := certStore.NewCertStore("apiserver-ca")
	if err != nil {
		log.Fatal(err)
	}

	// generate server's tls cert signed by ca
	serverCertConfig := cert.Config{
		CommonName:   "kube-apiserver-tls-cert",
		Organization: []string{"kubernetes"},
		AltNames: cert.AltNames{
			DNSNames: []string{"kube-apiserver.com"},
			IPs:      []net.IP{net.ParseIP("127.0.0.1")},
		},
		Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverKey, serverCert, err := tlsStore.NewSignedCert(serverCertConfig)
	if err != nil {
		log.Fatal(err)
	}

	if err := certStore.Write("server-ca", tlsStore.CaCert, tlsStore.CaKey); err != nil {
		log.Fatal(err)
	}
	if err := certStore.Write("server", serverCert, serverKey); err != nil {
		log.Fatal(err)
	}

	rhClientStore, err := certStore.NewCertStore("rhclient-ca")
	if err != nil {
		log.Fatal(err)
	}
	rhClientCertConfig := cert.Config{
		CommonName:   "requestheader",
		Organization: []string{"requestheader"},
		AltNames: cert.AltNames{
			DNSNames: []string{"requestheader"},
			//IPs: []net.IP{net.ParseIP("127.0.0.1")},
		},
		Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	rhClientKey, rhClientCert, err := rhClientStore.NewSignedCert(rhClientCertConfig)

	if err := certStore.Write("rhclient-ca", rhClientStore.CaCert, rhClientStore.CaKey); err != nil {
		log.Fatal(err)
	}
	if err := certStore.Write("rhclient", rhClientCert, rhClientKey); err != nil {
		log.Fatal(err)
	}

	rhClientStore2, err := certStore.NewCertStore("rhclient-ca2")
	if err != nil {
		log.Fatal(err)
	}
	rhClientCertConfig2 := cert.Config{
		CommonName:   "tahsin",
		Organization: []string{"tahsin"},
		AltNames: cert.AltNames{
			DNSNames: []string{"tahsin"},
			//IPs: []net.IP{net.ParseIP("127.0.0.1")},
		},
		Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	rhClientKey2, rhClientCert2, err := rhClientStore2.NewSignedCert(rhClientCertConfig2)

	if err := certStore.Write("rhclient2", rhClientCert2, rhClientKey2); err != nil {
		log.Fatal(err)
	}

	// generate CA that signs the api-server's tls cert
	dbtlsStore, err := certStore.NewCertStore("db-apiserver-ca")
	if err != nil {
		log.Fatal(err)
	}

	// generate server's tls cert signed by ca
	dbserverCertConfig := cert.Config{
		CommonName:   "db-apiserver-tls-cert",
		Organization: []string{"kubernetes"},
		AltNames: cert.AltNames{
			DNSNames: []string{"db-apiserver.com"},
			IPs:      []net.IP{net.ParseIP("127.0.0.2")},
		},
		Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	dbserverKey, dbserverCert, err := dbtlsStore.NewSignedCert(dbserverCertConfig)
	if err != nil {
		log.Fatal(err)
	}

	if err := certStore.Write("db-server-ca", dbtlsStore.CaCert, dbtlsStore.CaKey); err != nil {
		log.Fatal(err)
	}
	if err := certStore.Write("db-server", dbserverCert, dbserverKey); err != nil {
		log.Fatal(err)
	}
}
