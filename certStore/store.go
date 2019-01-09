package certStore

import (
	"crypto/rsa"
	"crypto/x509"
	"io/ioutil"
	"path/filepath"

	"k8s.io/client-go/util/cert"
)

type certStore struct {
	location string
	CaCert   *x509.Certificate
	CaKey    *rsa.PrivateKey
}

func NewCertStore(location string) (*certStore, error) {
	certStore := &certStore{
		location: location,
	}
	if err := certStore.newCA(); err != nil {
		return nil, err
	}

	return certStore, nil
}

func (c *certStore) newCA() error {
	// generate keys
	caKey, err := cert.NewPrivateKey()
	if err != nil {
		return err
	}

	// generate ca cert
	caCert, err := cert.NewSelfSignedCACert(
		cert.Config{
			CommonName: filepath.Base(c.location),
		},
		caKey,
	)
	if err != nil {
		return err
	}

	c.CaKey = caKey
	c.CaCert = caCert

	return nil
}

func Write(name string, certificate *x509.Certificate, key *rsa.PrivateKey) error {
	if err := ioutil.WriteFile(name+".crt", cert.EncodeCertPEM(certificate), 0644); err != nil {
		return err
	}
	if err := ioutil.WriteFile(name+".key", cert.EncodePrivateKeyPEM(key), 0644); err != nil {
		return err
	}

	return nil
}

func (c *certStore) NewSignedCert(opt cert.Config) (*rsa.PrivateKey, *x509.Certificate, error) {
	serverKey, err := cert.NewPrivateKey()
	if err != nil {
		return nil, nil, err
	}
	serverCert, err := cert.NewSignedCert(opt, serverKey, c.CaCert, c.CaKey)
	if err != nil {
		return nil, nil, err
	}
	return serverKey, serverCert, nil
}
