package signer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"thresholdvault/internal/identity"
	"thresholdvault/internal/sharestore"
)

// PeerResolver returns the trusted public identity of another signer.
type PeerResolver interface {
	Resolve(name string) (*identity.Public, error)
}

// StaticPeers is a fixed name → identity map (configured out of band).
type StaticPeers map[string]*identity.Public

func (s StaticPeers) Resolve(name string) (*identity.Public, error) {
	p, ok := s[name]
	if !ok {
		return nil, fmt.Errorf("signer: no identity configured for peer %q", name)
	}
	return p, nil
}

// DirPeers reads "<Dir>/<name>.pub" files and pins the first identity seen
// for each peer in the signer's own encrypted store (trust on first use).
// A later change to a peer's file is refused, which defeats key substitution
// by whoever can write the shared directory after setup.
type DirPeers struct {
	Dir   string
	Store *sharestore.Store
}

func (d *DirPeers) Resolve(name string) (*identity.Public, error) {
	raw, err := os.ReadFile(filepath.Join(d.Dir, name+".pub"))
	if err != nil {
		return nil, fmt.Errorf("signer: read identity of %q: %w", name, err)
	}
	pub, err := identity.ParsePublic(string(raw))
	if err != nil {
		return nil, err
	}
	if pub.Name != name {
		return nil, fmt.Errorf("signer: identity file for %q names %q", name, pub.Name)
	}
	pinName := "peer/" + name
	pinned, err := d.Store.Get(pinName)
	switch {
	case errors.Is(err, sharestore.ErrNotFound):
		if err := d.Store.Put(pinName, []byte(pub.String())); err != nil {
			return nil, err
		}
		return pub, nil
	case err != nil:
		return nil, err
	}
	if string(pinned) != pub.String() {
		return nil, fmt.Errorf("signer: identity of %q changed since it was pinned (refusing; possible key substitution)", name)
	}
	return pub, nil
}

// PublishIdentity writes this signer's public identity to "<dir>/<name>.pub".
func PublishIdentity(dir string, pub *identity.Public) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, pub.Name+".pub"), []byte(pub.String()+"\n"), 0o644)
}
