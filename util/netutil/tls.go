package netutil

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path"
	"sync"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/util/errors"
	"github.com/floating-cat/heteroglossia/util/ioutil"
	"github.com/floating-cat/heteroglossia/util/log"
	"github.com/floating-cat/heteroglossia/util/osutil"
)

var (
	tlsH2ClientConfigMap    = make(map[string]*tls.Config)
	tlsH3ClientConfigMap    = make(map[string]*tls.Config)
	tlsClientConfigMapMutex sync.Mutex

	tlsH2ServerConfigMap    = make(map[string]*tls.Config)
	tlsH3ServerConfigMap    = make(map[string]*tls.Config)
	tlsServerConfigMapMutex sync.Mutex

	h2ALPN = []string{"h2", "http/1.1"}
	h3ALPN = []string{"h3"}

	tlsKeyLogFileRemovalOnce sync.Once
)

const tlsKeyLogFilepath = "logs/tls_key.log"

func TLSClientConfig(host string, tlsCustomCertFile string, tlsKeyLog bool, http3 bool) (*tls.Config, error) {
	tlsClientConfigMapMutex.Lock()
	defer tlsClientConfigMapMutex.Unlock()
	var tlsConfig *tls.Config
	var ok bool
	if http3 {
		tlsConfig, ok = tlsH3ClientConfigMap[host]
	} else {
		tlsConfig, ok = tlsH2ClientConfigMap[host]
	}
	if ok {
		return tlsConfig, nil
	}

	if tlsCustomCertFile == "" {
		tlsConfig = &tls.Config{ServerName: host}
	} else {
		certBs, err := ioutil.ReadFile(tlsCustomCertFile)
		if err != nil {
			return nil, err
		}
		certPool := x509.NewCertPool()
		block, _ := pem.Decode(certBs)
		if block == nil {
			return nil, errors.New("fail to decode the TLS certificate file")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		// https://stackoverflow.com/a/73912711
		if len(cert.DNSNames) == 0 {
			return nil, errors.New("no DNSNames in the TLS certificate")
		}
		certPool.AppendCertsFromPEM(certBs)
		tlsConfig = &tls.Config{
			RootCAs:    certPool,
			ServerName: cert.DNSNames[0],
		}
	}
	if tlsKeyLog {
		err := os.MkdirAll(path.Dir(tlsKeyLogFilepath), 0700)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		tlsKeyLogFile, err := os.OpenFile(tlsKeyLogFilepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		tlsConfig.KeyLogWriter = tlsKeyLogFile

		tlsKeyLogFileRemovalOnce.Do(func() {
			osutil.RegisterProgramTerminationHandler(func() {
				err := os.Remove(tlsKeyLogFilepath)
				if err != nil {
					log.WarnWithError("fail to remove the file", err, "path", tlsKeyLogFilepath)
				}
			})
		})
	}
	tlsConfig.NextProtos = h2ALPN
	tlsConfig.ClientSessionCache = tls.NewLRUClientSessionCache(0)
	tlsH3Config := tlsConfig.Clone()
	tlsH3Config.NextProtos = h3ALPN
	tlsH3Config.ClientSessionCache = tls.NewLRUClientSessionCache(0)

	tlsH2ClientConfigMap[host] = tlsConfig
	tlsH3ClientConfigMap[host] = tlsH3Config
	if http3 {
		return tlsH3Config, nil
	}
	return tlsConfig, nil
}

func TLSServerConfig(host string, tlsCertKeyPair *conf.TLSCertKeyPair, http3 bool) (*tls.Config, error) {
	tlsServerConfigMapMutex.Lock()
	defer tlsServerConfigMapMutex.Unlock()

	var tlsConfig *tls.Config
	var ok bool
	if http3 {
		tlsConfig, ok = tlsH3ServerConfigMap[host]
	} else {
		tlsConfig, ok = tlsH2ServerConfigMap[host]
	}
	if ok {
		return tlsConfig, nil
	}

	if tlsCertKeyPair == nil {
		// use context.Background() for reusing the same tls.Config for different server types,
		// otherwise cancel one context can stop tls.Config used by others
		tlsConfig = tlsConfigWithAutomatedCertificate(context.Background(), host)
	} else {
		cert, err := tls.LoadX509KeyPair(tlsCertKeyPair.CertFile, tlsCertKeyPair.KeyFile)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	}
	tlsConfig.NextProtos = h2ALPN
	tlsConfig.ClientSessionCache = tls.NewLRUClientSessionCache(0)
	tlsH3Config := tlsConfig.Clone()
	tlsH3Config.NextProtos = h3ALPN
	tlsH3Config.ClientSessionCache = tls.NewLRUClientSessionCache(0)

	tlsH2ServerConfigMap[host] = tlsConfig
	tlsH3ServerConfigMap[host] = tlsH3Config

	if http3 {
		return tlsH3Config, nil
	}
	return tlsConfig, nil
}
