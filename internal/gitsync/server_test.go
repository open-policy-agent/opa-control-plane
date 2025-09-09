package gitsync_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net"
	"path/filepath"

	"github.com/gliderlabs/ssh"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/server"
	crypto_ssh "golang.org/x/crypto/ssh"
)

// GitSSHServer is a simple git SSH server. It supports only cloning/fetching and SSH key authentication at the moment.
type GitSSHServer struct {
	address  string       // Empty string for all interfaces
	port     int          // 0 for auto-assigned port
	dir      string       // Directory for git repository (with HEAD, info, objects, refs folders/files)
	listener net.Listener // Listener for incoming SSH connections
	hostKey  ssh.Signer   // auto-generated ssh server host key
	server   *ssh.Server
}

func NewGitSSHServer(network string, address string, port int, dir string, authorizedKey ssh.PublicKey) (*GitSSHServer, error) {
	l, err := net.Listen(network, fmt.Sprintf("%s:%d", address, port))
	if err != nil {
		return nil, err
	}

	var s GitSSHServer
	s.address = address
	s.port = port
	s.dir = dir
	s.listener = l
	s.server = &ssh.Server{
		Handler: s.handleSSH,
		PublicKeyHandler: func(ctx ssh.Context, key ssh.PublicKey) bool {
			if authorizedKey == nil {
				return true // No authorization required
			}

			return ssh.KeysEqual(key, authorizedKey)
		},
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	s.hostKey, err = crypto_ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}

	s.server.AddHostKey(s.hostKey)

	return &s, nil
}

func (s *GitSSHServer) Address() net.Addr {
	return s.listener.Addr()
}

func (s *GitSSHServer) Fingerprint() string {
	return crypto_ssh.FingerprintSHA256(s.hostKey.PublicKey())
}

func (s *GitSSHServer) Serve() error {
	return s.server.Serve(s.listener)
}

func (s *GitSSHServer) handleSSH(sess ssh.Session) {
	cmd := sess.Command()

	if len(cmd) == 0 {
		fmt.Fprintf(sess.Stderr(), "ERR: no command\n")
		_ = sess.Exit(1)
		return
	}

	switch cmd[0] {
	case "git-upload-pack":
		if err := serveUploadPack(sess.Context(), sess, s.dir, cmd); err != nil {
			fmt.Fprintf(sess.Stderr(), "ERR: %v\n", err)
			_ = sess.Exit(128)
			return
		}

		_ = sess.Exit(1)

	default:
		fmt.Fprintf(sess.Stderr(), "ERR: unknown command: %v\n", cmd)
		_ = sess.Exit(1)
	}
}

func serveUploadPack(ctx context.Context, sess ssh.Session, dir string, cmd []string) (err error) {
	ep, err := transport.NewEndpoint(filepath.Join(dir, cmd[1]))
	if err != nil {
		return err
	}

	s, err := server.DefaultServer.NewUploadPackSession(ep, nil)
	if err != nil {
		return err
	}

	ar, err := s.AdvertisedReferences()
	if err != nil {
		return err
	}

	if err := ar.Encode(sess); err != nil {
		return err
	}

	req := packp.NewUploadPackRequest()
	if err := req.Decode(sess); err != nil {
		return err
	}

	resp, err := s.UploadPack(ctx, req)
	if err != nil {
		return err
	}

	return resp.Encode(sess)
}
