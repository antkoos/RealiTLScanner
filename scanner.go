package main

import (
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"
)

func StrictCheck(x509 *x509.Certificate, targetIP net.IP) bool {
	if len(x509.DNSNames) == 0 {
		return true
	}
	if !strict {
		return false
	}
	for _, dnsName := range x509.DNSNames {
		name := dnsName
		ips, err := net.LookupIP(name)
		if err != nil {
			continue
		}

		for _, ip := range ips {
			if !ip.Equal(targetIP) {
				return true
			}
		}
	}
	return false
}

func ScanTLS(host Host, out chan<- string, geo *Geo) {
	if host.IP == nil {
		ip, err := LookupIP(host.Origin)
		if err != nil {
			slog.Debug("Failed to get IP from the origin", "origin", host.Origin, "err", err)
			return
		}
		host.IP = ip
	}
	hostPort := net.JoinHostPort(host.IP.String(), strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", hostPort, time.Duration(timeout)*time.Second)
	if err != nil {
		slog.Debug("Cannot dial", "target", hostPort)
		return
	}
	defer conn.Close()
	err = conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	if err != nil {
		slog.Error("Error setting deadline", "err", err)
		return
	}
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		CurvePreferences:   []tls.CurveID{tls.X25519, tls.X25519MLKEM768},
	}
	if host.Type == HostTypeDomain {
		tlsCfg.ServerName = host.Origin
	}
	c := tls.Client(conn, tlsCfg)
	err = c.Handshake()
	if err != nil {
		slog.Debug("TLS handshake failed", "target", hostPort)
		return
	}
	state := c.ConnectionState()
	alpn := state.NegotiatedProtocol
	domains := strings.Join(state.PeerCertificates[0].DNSNames, ", ")
	issuers := strings.Join(state.PeerCertificates[0].Issuer.Organization, " | ")
	length := 0
	leaf := state.PeerCertificates[0]
	for _, cert := range state.PeerCertificates {
		length += len(cert.Raw)
		//if len(cert.DNSNames) != 0 {
		//	leaf = cert
		//}
	}

	log := slog.Info
	feasible := true
	geoCode := geo.GetGeo(host.IP)

	if state.Version != tls.VersionTLS13 || alpn != "h2" || len(issuers) == 0 || StrictCheck(leaf, host.IP) {
		// not feasible
		log = slog.Debug
		feasible = false
	} else {
		out <- strings.Join([]string{
			host.IP.String(),
			host.Origin,
			tls.VersionName(state.Version),
			alpn,
			state.CurveID.String(),
			strconv.Itoa(length) + "(certs count: " + strconv.Itoa(len(state.PeerCertificates)) + ")",
			leaf.SignatureAlgorithm.String(),
			leaf.PublicKeyAlgorithm.String(),
			domains,
			"\"" + issuers + "\"",
			geoCode}, ",") + "\n"
	}
	log("Connected to target", "feasible", feasible,
		"ip", host.IP.String(),
		"origin", host.Origin,
		"tls", tls.VersionName(state.Version),
		"alpn", alpn,
		"curve", state.CurveID.String(),
		"cert-length", strconv.Itoa(length)+"(certs count: "+strconv.Itoa(len(state.PeerCertificates))+")",
		"cert-signature", leaf.SignatureAlgorithm.String(),
		"cert-publickey", leaf.PublicKeyAlgorithm.String(),
		"cert-domains", domains,
		"cert-issuer", issuers,
		"geo", geoCode)
}
