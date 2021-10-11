package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"strings"
)

func main() {
	keychains := []string{
		"/Library/Keychains/System.keychain",
		"/System/Library/Keychains/SystemRootCertificates.keychain",
	}

	prefix := os.Args[1]
	certdir := os.Args[2]

	cmd := exec.Command("security", "find-certificate", "-a", "-p")
	cmd.Args = append(cmd.Args, keychains...)

	out, err := cmd.Output()
	if err != nil {
		panic(err)
	}

	certs := strings.Split(string(out), "-----BEGIN CERTIFICATE-----\n")
	var valid_certs []string

	for _, cert := range certs {
		var err bytes.Buffer
		cmd = exec.Command("openssl", "x509", "-inform", "pem", "-checkend", "0", "-noout")

		cmd.Stdin = strings.NewReader("-----BEGIN CERTIFICATE-----\n" + cert)
		cmd.Stderr = &err

		cmd.Run()
		cmd.Wait()

		if len(err.String()) != 0 {
			fmt.Println(err.String())
		}

		var out bytes.Buffer
		cmd = exec.Command("openssl", "x509", "-inform", "pem", "-purpose", "-noout")

		cmd.Stdin = strings.NewReader("-----BEGIN CERTIFICATE-----\n" + cert)
		cmd.Stdout = &out

		cmd.Run()
		cmd.Wait()

		if strings.Contains(out.String(), "SSL server CA : Yes") {
			valid_certs = append(valid_certs, ("-----BEGIN CERTIFICATE-----\n" + cert))
		}
	}

	var trusted_certs []string

	for _, cert := range valid_certs {
		f, err := ioutil.TempFile("", "tmp.pem")
		defer os.Remove(f.Name())

		if err != nil {
			panic(err)
		}

		f.Write([]byte(cert))
		f.Close()

		cmd := exec.Command("security", "verify-cert", "-l", "-L", "-c", f.Name())
		_, err = cmd.Output()

		if err != nil {
			fmt.Println("invalid certificate")
		}

		trusted_certs = append(trusted_certs, cert)
	}

	fingerprints := map[string]bool{}

	for _, cert := range trusted_certs {
		cmd := exec.Command("openssl", "x509", "-inform", "pem", "-fingerprint", "-sha256", "-noout")
		cmd.Stdin = strings.NewReader(cert)
		out, err := cmd.Output()

		if err != nil {
			fmt.Println(err)
		}

		fingerprints[string(out)] = true
	}

	dat, err := os.ReadFile(path.Join(prefix, "cacert.pem"))

	if err != nil {
		panic(err)
	}

	ca_certs := strings.Split(string(dat), "-----BEGIN CERTIFICATE-----\n")

	for _, cert := range ca_certs {
		cmd := exec.Command("openssl", "x509", "-inform", "pem", "-fingerprint", "-sha256", "-noout")
		cmd.Stdin = strings.NewReader("-----BEGIN CERTIFICATE-----\n" + cert)
		out, err := cmd.Output()

		if err != nil {
			fmt.Println(err)
		}

		if !fingerprints[string(out)] {
			fingerprints[string(out)] = true

			header := "-----BEGIN CERTIFICATE-----\n"
			if string(cert[0:1]) == "#" {
				header = ""
			}

			trusted_certs = append(trusted_certs, header+cert)
		}
	}

	fmt.Println(fingerprints)
	os.WriteFile(path.Join(certdir, "cert.pem"), []byte(strings.Join(trusted_certs, "\n")), 0644)
}
