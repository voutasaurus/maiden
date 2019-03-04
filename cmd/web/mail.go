package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"
)

type mail struct {
	mailConn
	subject string
	to      []string
	msg     []byte
}

type mailConn struct {
	host string
	port string
	from string
	pass string
}

func (m mail) send() error {
	auth := smtp.PlainAuth("", m.from, m.pass, m.host)

	b := new(bytes.Buffer)
	fmt.Fprintf(b, "From: %s\r\n", m.from)
	fmt.Fprintf(b, "To: %s\r\n", strings.Join(m.to, ";"))
	fmt.Fprintf(b, "Subject: %s\r\n\r\n", m.subject)
	if _, err := b.Write(m.msg); err != nil {
		return err
	}

	return connAndSend(m.host+":"+m.port, auth, m.from, m.to, b.Bytes())
}

func (m *mailer) send(email, link string) error {
	m.log.Printf("sending %q to %q", link, email)
	return mail{
		mailConn: m.mail,
		subject:  "Verify your email address",
		to:       []string{email},
		msg:      format(link),
	}.send()
}

func format(link string) []byte {
	// TODO: html template for link email
	return []byte(link)
}

func connAndSend(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	conn, err := tls.Dial("tcp", addr, nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	client, err := smtp.NewClient(conn, addrToHost(addr))
	if err != nil {
		return err
	}
	defer client.Quit()
	if err := client.Auth(auth); err != nil {
		return err
	}
	if err := client.Mail(from); err != nil {
		return err
	}
	for _, r := range to {
		if err := client.Rcpt(r); err != nil {
			return err
		}
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	defer w.Close()
	_, err = w.Write(msg)
	return err
}

// TODO: handle ipv6 for addrTo* funcs
func addrToHost(addr string) string {
	return strings.Split(addr, ":")[0]
}

func addrToPort(addr string) string {
	return strings.Split(addr, ":")[1]
}
