package gitsync_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/gitsync"
	"golang.org/x/crypto/ssh"
)

// TestGitsyncLocal tests the functionality of the gitsync package by creating a temporary git repository on disk.
// committing a file, cloning it to a new location using the gitsync, and verifying that the cloned repository contains the expected content.
// It tests both the initial clone and subsequent updates to the repository.
func TestGitsyncLocal(t *testing.T) {
	// Create a git repository to use for testing.

	testRepositoryPath := t.TempDir() + "/testing"
	repository, err := git.PlainInit(testRepositoryPath, false)
	if err != nil {
		t.Fatalf("expected no error while initializing test repository: %v", err)
	}

	err = os.WriteFile(testRepositoryPath+"/README", []byte("first commit"), 0644)
	if err != nil {
		t.Fatalf("expected no error while creating new file: %v", err)
	}

	w, err := repository.Worktree()
	if err != nil {
		t.Fatalf("expected no error while getting worktree: %v", err)
	}
	_, err = w.Add("README")
	if err != nil {
		t.Fatalf("expected no error while adding file to worktree: %v", err)
	}

	_, err = w.Commit("README", &git.CommitOptions{Author: &object.Signature{}})
	if err != nil {
		t.Fatalf("expected no error while committing changes: %v", err)
	}

	// Create a new synchronizer with an empty directory to clone a repository into.
	clonedRepositoryPath := t.TempDir() + "/test-repo"

	ref := "refs/heads/master"
	s := gitsync.New(clonedRepositoryPath, config.Git{
		Repo:      testRepositoryPath,
		Reference: &ref,
		Commit:    nil,
	}, "")

	ctx := t.Context()
	if err := s.Execute(ctx); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Check if the repository was created successfully.
	_, err = git.PlainOpen(clonedRepositoryPath)
	if err != nil {
		t.Fatalf("expected repository to be opened, got error: %v", err)
	}

	data, err := os.ReadFile(clonedRepositoryPath + "/README")
	if err != nil {
		t.Fatalf("expected no error while reading file, got: %v", err)
	}

	if string(data) != "first commit" {
		t.Fatalf("expected file content to be 'first commit', got: %s", string(data))
	}

	// Test synchronization by committing an update to the cloned repository.

	err = os.WriteFile(testRepositoryPath+"/README", []byte("second commit"), 0644)
	if err != nil {
		t.Fatalf("expected no error while creating new file: %v", err)
	}

	_, err = w.Add("README")
	if err != nil {
		t.Fatalf("expected no error while adding file to worktree: %v", err)
	}

	_, err = w.Commit("README", &git.CommitOptions{Author: &object.Signature{}})
	if err != nil {
		t.Fatalf("expected no error while committing changes: %v", err)
	}

	err = s.Execute(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	data, err = os.ReadFile(clonedRepositoryPath + "/README")
	if err != nil {
		t.Fatalf("expected no error while reading file, got: %v", err)
	}

	if string(data) != "second commit" {
		t.Fatalf("expected file content to be 'second commit', got: %s", string(data))
	}
}

// TestGitsyncSSH tests the functionality of the gitsync package with an SSH server.
// It creates a temporary git repository, commits a file, and then uses the gitsync package to clone the repository over SSH.
// It verifies that the cloned repository contains the expected content.
// It also tests the SSH key authentication by generating a new SSH key for the server and using it to authenticate the client.
func TestGitsyncSSH(t *testing.T) {
	// Create a git repository to use for testing. Note, it's not a bare repository, but it will be used as such by pointing to .git directory.
	tmpRootDir := t.TempDir()
	testRepositoryPath := tmpRootDir + "/testing"

	repository, err := git.PlainInit(testRepositoryPath, false)
	if err != nil {
		t.Fatalf("expected no error while initializing test repository: %v", err)
	}

	if err := os.WriteFile(testRepositoryPath+"/README", []byte("first commit"), 0644); err != nil {
		t.Fatalf("expected no error while creating new file: %v", err)
	}

	w, err := repository.Worktree()
	if err != nil {
		t.Fatalf("expected no error while getting worktree: %v", err)
	}
	_, err = w.Add("README")
	if err != nil {
		t.Fatalf("expected no error while adding file to worktree: %v", err)
	}

	commitHash, err := w.Commit("README", &git.CommitOptions{Author: &object.Signature{}})
	if err != nil {
		t.Fatalf("expected no error while committing changes: %v", err)
	}
	// add another commit
	if err := os.WriteFile(testRepositoryPath+"/README", []byte("second commit"), 0644); err != nil {
		t.Fatalf("expected no error while creating new file: %v", err)
	}

	_, err = w.Add("README")
	if err != nil {
		t.Fatalf("expected no error while adding file to worktree: %v", err)
	}

	if _, err := w.Commit("README", &git.CommitOptions{Author: &object.Signature{}}); err != nil {
		t.Fatalf("expected no error while committing changes: %v", err)
	}

	// Set up a git SSH server to serve the repository.
	sshKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("expected no error while generating SSH key: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(sshKey)
	if err != nil {
		t.Fatalf("expected no error while creating SSH signer: %v", err)
	}

	srv, err := NewGitSSHServer("tcp", "127.0.0.1", 0, tmpRootDir, signer.PublicKey())
	if err != nil {
		srv, err = NewGitSSHServer("tcp6", "[::1]", 0, tmpRootDir, signer.PublicKey())
		if err != nil {
			t.Fatalf("expected no error while creating git SSH server: %v", err)
		}
	}

	go func() {
		if err := srv.Serve(); err != nil {
			panic(fmt.Sprintf("expected no error while starting server: %v", err))
		}
	}()

	// Start Git SSH server.

	passphrase := "passphrase"

	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(sshKey),
	}

	// nolint:staticcheck
	block, err = x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(passphrase), x509.PEMCipherAES256)
	if err != nil {
		t.Fatalf("expected no error while encrypting PEM block: %v", err)
	}

	secret := config.SecretSSHKey{
		Key:          string(pem.EncodeToMemory(block)),
		Passphrase:   passphrase,
		Fingerprints: []string{srv.Fingerprint()},
	}

	bs, err := json.Marshal(secret)
	if err != nil {
		t.Fatalf("expected no error while marshaling secret: %v", err)
	}

	var value map[string]interface{}
	if err := json.Unmarshal(bs, &value); err != nil {
		t.Fatalf("expected no error while unmarshaling secret: %v", err)
	}

	value["type"] = "ssh_key"

	secret2 := config.Secret{
		Name:  "ssh",
		Value: value,
	}

	t.Run("clone remote branch", func(t *testing.T) {
		// Create a new synchronizer with the SSH repository URL and the secret.
		clonedRepositoryPath := tmpRootDir + "/test-repo"
		repoDir := "testing/.git" // point to .git to simulate bare repository
		repoURL := fmt.Sprintf("ssh://git@%s/%s", srv.Address().String(), repoDir)
		t.Cleanup(srv.ResetFetches)

		ref := "refs/heads/master"
		s := gitsync.New(clonedRepositoryPath, config.Git{
			Repo:        repoURL,
			Reference:   &ref,
			Credentials: secret2.Ref(),
		}, "")

		if err := s.Execute(t.Context()); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		data, err := os.ReadFile(clonedRepositoryPath + "/README")
		if err != nil {
			t.Fatalf("expected no error while reading file, got: %v", err)
		}

		if string(data) != "second commit" {
			t.Fatalf("expected file content to be 'second commit', got: %s", string(data))
		}

		if exp, act := uint32(1), srv.Fetches(); exp != act {
			t.Errorf("expected %d fetches, got %d", exp, act)
		}
	})

	t.Run("clone remote commit", func(t *testing.T) {
		// Create a new synchronizer with the SSH repository URL and the secret.
		clonedRepositoryPath := tmpRootDir + "/test-repo"
		repoDir := "testing/.git" // point to .git to simulate bare repository
		repoURL := fmt.Sprintf("ssh://git@%s/%s", srv.Address().String(), repoDir)
		t.Cleanup(srv.ResetFetches)

		ref := commitHash.String()
		s := gitsync.New(clonedRepositoryPath, config.Git{
			Repo:        repoURL,
			Commit:      &ref,
			Credentials: secret2.Ref(),
		}, "")

		if err := s.Execute(t.Context()); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		data, err := os.ReadFile(clonedRepositoryPath + "/README")
		if err != nil {
			t.Fatalf("expected no error while reading file, got: %v", err)
		}

		if string(data) != "first commit" {
			t.Fatalf("expected file content to be 'first commit', got: %s", string(data))
		}

		// Run again. Expect no new fetch since we've already got the commit.
		if err := s.Execute(t.Context()); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if exp, act := uint32(1), srv.Fetches(); exp != act {
			t.Errorf("expected %d fetches, got %d", exp, act)
		}
	})
}
