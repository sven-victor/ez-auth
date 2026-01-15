// Copyright 2026 Sven Victor
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package model

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"reflect"
	"testing"
)

func TestParsePrivateKey(t *testing.T) {
	type testArgs struct {
		keyAlgorithm string
		privateKey   string
		want         any
	}
	tests := []struct {
		name     string
		argsFunc func() testArgs
		wantErr  bool
	}{
		{
			name: "test-hmac",
			argsFunc: func() testArgs {
				return testArgs{
					keyAlgorithm: "HS256",
					privateKey:   base64.StdEncoding.EncodeToString([]byte("secret")),
					want:         []byte("secret"),
				}
			},
			wantErr: false,
		},
		{
			name: "test-rsa",
			argsFunc: func() testArgs {
				rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatalf("failed to generate RSA private key: %v", err)
				}
				rsaPrivateKeyBytes := x509.MarshalPKCS1PrivateKey(rsaPrivateKey)
				return testArgs{
					keyAlgorithm: "RS256",
					privateKey:   string(rsaPrivateKeyBytes),
					want:         rsaPrivateKey,
				}
			},
		},
		{
			name: "test-rsa-pem",
			argsFunc: func() testArgs {
				rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatalf("failed to generate RSA private key: %v", err)
				}
				rsaPrivateKeyBytes := x509.MarshalPKCS1PrivateKey(rsaPrivateKey)
				// encode to pem format
				rsaPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{
					Type:  "RSA PRIVATE KEY",
					Bytes: rsaPrivateKeyBytes,
				})
				return testArgs{
					keyAlgorithm: "RS256",
					privateKey:   string(rsaPrivateKeyPEM),
					want:         rsaPrivateKey,
				}
			},
		},
		{
			name: "test-rsa-pem-base64",
			argsFunc: func() testArgs {
				rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatalf("failed to generate RSA private key: %v", err)
				}
				rsaPrivateKeyBytes := x509.MarshalPKCS1PrivateKey(rsaPrivateKey)

				// encode to pem format
				rsaPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{
					Type:  "RSA PRIVATE KEY",
					Bytes: rsaPrivateKeyBytes,
				})
				return testArgs{
					keyAlgorithm: "RS256",
					privateKey:   base64.StdEncoding.EncodeToString(rsaPrivateKeyPEM),
					want:         rsaPrivateKey,
				}
			},
		},
		{
			name: "test-rsa-pem-base64-nopadding",
			argsFunc: func() testArgs {
				rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatalf("failed to generate RSA private key: %v", err)
				}
				rsaPrivateKeyBytes := x509.MarshalPKCS1PrivateKey(rsaPrivateKey)

				// encode to pem format
				rsaPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{
					Type:  "RSA PRIVATE KEY",
					Bytes: rsaPrivateKeyBytes,
				})
				return testArgs{
					keyAlgorithm: "RS256",
					privateKey:   base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString(rsaPrivateKeyPEM),
					want:         rsaPrivateKey,
				}
			},
		},
		// ECDSA
		{
			name: "test-ecdsa",
			argsFunc: func() testArgs {
				ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatalf("failed to generate ECDSA private key: %v", err)
				}
				ecdsaPrivateKeyBytes, err := x509.MarshalECPrivateKey(ecdsaPrivateKey)
				if err != nil {
					t.Fatalf("failed to marshal ECDSA private key: %v", err)
				}
				return testArgs{
					keyAlgorithm: "ES256",
					privateKey:   string(ecdsaPrivateKeyBytes),
					want:         ecdsaPrivateKey,
				}
			},
			wantErr: false,
		},
		{
			name: "test-ecdsa-pem",
			argsFunc: func() testArgs {
				ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatalf("failed to generate ECDSA private key: %v", err)
				}
				ecdsaPrivateKeyBytes, err := x509.MarshalECPrivateKey(ecdsaPrivateKey)
				if err != nil {
					t.Fatalf("failed to marshal ECDSA private key: %v", err)
				}
				ecdsaPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{
					Type:  "ECDSA PRIVATE KEY",
					Bytes: ecdsaPrivateKeyBytes,
				})
				return testArgs{
					keyAlgorithm: "ES256",
					privateKey:   string(ecdsaPrivateKeyPEM),
					want:         ecdsaPrivateKey,
				}
			},
			wantErr: false,
		},
		{
			name: "test-ecdsa-pem-base64",
			argsFunc: func() testArgs {
				ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatalf("failed to generate ECDSA private key: %v", err)
				}
				ecdsaPrivateKeyBytes, err := x509.MarshalECPrivateKey(ecdsaPrivateKey)
				if err != nil {
					t.Fatalf("failed to marshal ECDSA private key: %v", err)
				}
				ecdsaPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{
					Type:  "ECDSA PRIVATE KEY",
					Bytes: ecdsaPrivateKeyBytes,
				})
				return testArgs{
					keyAlgorithm: "ES256",
					privateKey:   base64.StdEncoding.EncodeToString(ecdsaPrivateKeyPEM),
					want:         ecdsaPrivateKey,
				}
			},
		},
		{
			name: "test-ecdsa-pem-base64-nopadding",
			argsFunc: func() testArgs {
				ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatalf("failed to generate ECDSA private key: %v", err)
				}
				ecdsaPrivateKeyBytes, err := x509.MarshalECPrivateKey(ecdsaPrivateKey)
				if err != nil {
					t.Fatalf("failed to marshal ECDSA private key: %v", err)
				}
				ecdsaPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{
					Type:  "ECDSA PRIVATE KEY",
					Bytes: ecdsaPrivateKeyBytes,
				})
				return testArgs{
					keyAlgorithm: "ES256",
					privateKey:   base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString(ecdsaPrivateKeyPEM),
					want:         ecdsaPrivateKey,
				}
			},
		},
		// ECDSA
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.argsFunc()
			got, err := ParsePrivateKey(args.privateKey, args.keyAlgorithm)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePrivateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, args.want) {
				t.Errorf("ParsePrivateKey() got = %v, want %v", got, args.want)
			}
		})
	}
}
