# generate-ca-certificates

Package for regenerating CA certificate bundle.
Built for Pakket (MacOS package manager).

## usage

```generate-ca-certificates <prefix> <certdir>```

prefix: The directory from where the downloaded cacert.pem file is read.
certdir: The output directory where the cert.pem file will end.

## Build

```go build .```