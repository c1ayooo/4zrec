package datasource

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

type DB interface {
	Exec(string, ...any) (sql.Result, error)
	Query(string, ...any) (*sql.Rows, error)
	QueryRow(string, ...any) *sql.Row
}
type Store struct {
	db  DB
	key []byte
}

func NewStore(db DB, key []byte) (*Store, error) {
	if len(key) != 32 {
		return nil, errors.New("datasource encryption key must be 32 bytes")
	}
	s := &Store{db: db, key: key}
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS datasource_sessions (id TEXT PRIMARY KEY, owner TEXT NOT NULL, project TEXT NOT NULL DEFAULT '', provider TEXT NOT NULL, config_ciphertext TEXT NOT NULL, revision BIGINT NOT NULL DEFAULT 1, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL)`)
	return s, err
}

// LoadOrCreateKey keeps this vault independent from config.yaml and other vaults.
func LoadOrCreateKey(path string, create bool) ([]byte, error) {
	if b, e := os.ReadFile(path); e == nil {
		if len(b) < 32 {
			return nil, errors.New("datasource key too short")
		}
		return b[:32], nil
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	if !create {
		return nil, errors.New("datasource key missing")
	}
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return nil, e
	}
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, e
	}
	if e := os.WriteFile(path, b, 0600); e != nil {
		return nil, e
	}
	return b, nil
}
func (s *Store) encrypt(v map[string]string) (string, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return "", e
	}
	block, e := aes.NewCipher(s.key)
	if e != nil {
		return "", e
	}
	g, e := cipher.NewGCM(block)
	if e != nil {
		return "", e
	}
	n := make([]byte, g.NonceSize())
	if _, e = io.ReadFull(rand.Reader, n); e != nil {
		return "", e
	}
	return base64.RawStdEncoding.EncodeToString(g.Seal(n, n, b, nil)), nil
}
func (s *Store) decrypt(v string) (map[string]string, error) {
	b, e := base64.RawStdEncoding.DecodeString(v)
	if e != nil {
		return nil, e
	}
	block, e := aes.NewCipher(s.key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	if len(b) < g.NonceSize() {
		return nil, errors.New("invalid ciphertext")
	}
	p, e := g.Open(nil, b[:g.NonceSize()], b[g.NonceSize():], nil)
	if e != nil {
		return nil, e
	}
	var out map[string]string
	e = json.Unmarshal(p, &out)
	return out, e
}
func (s *Store) Upsert(r UpsertRequest) (Session, error) {
	r.Owner = strings.TrimSpace(r.Owner)
	r.Project = strings.TrimSpace(r.Project)
	r.Provider = strings.TrimSpace(r.Provider)
	if r.Owner == "" || r.Provider == "" {
		return Session{}, errors.New("owner and provider are required")
	}
	id := strings.TrimSpace(r.ID)
	if id == "" {
		id = uuid.NewString()
	}
	now := time.Now().UTC()
	enc, e := s.encrypt(r.Config)
	if e != nil {
		return Session{}, e
	}
	_, e = s.db.Exec(`INSERT INTO datasource_sessions (id,owner,project,provider,config_ciphertext,revision,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,1,$6,$6) ON CONFLICT (id) DO UPDATE SET owner=EXCLUDED.owner,project=EXCLUDED.project,provider=EXCLUDED.provider,config_ciphertext=EXCLUDED.config_ciphertext,revision=datasource_sessions.revision+1,updated_at=EXCLUDED.updated_at`, id, r.Owner, r.Project, r.Provider, enc, now)
	if e != nil {
		return Session{}, e
	}
	return s.Get(id)
}
func (s *Store) Get(id string) (Session, error) {
	var x Session
	var enc string
	err := s.db.QueryRow(`SELECT id,owner,project,provider,config_ciphertext,revision,created_at,updated_at FROM datasource_sessions WHERE id=$1`, id).Scan(&x.ID, &x.Owner, &x.Project, &x.Provider, &enc, &x.Revision, &x.CreatedAt, &x.UpdatedAt)
	if err != nil {
		return x, err
	}
	x.Config, err = s.decrypt(enc)
	return x, err
}
func (s *Store) List(owner, project string, all bool) ([]Metadata, error) {
	// list metadata only: secret ciphertext is never selected.
	rows, e := s.db.Query(`SELECT id,owner,project,provider,revision,created_at,updated_at,(config_ciphertext<>'') AS configured FROM datasource_sessions WHERE ($1='' OR owner=$1) AND ($2='' OR project=$2) ORDER BY updated_at DESC`, owner, project)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []Metadata
	for rows.Next() {
		var m Metadata
		if e = rows.Scan(&m.ID, &m.Owner, &m.Project, &m.Provider, &m.Revision, &m.CreatedAt, &m.UpdatedAt, &m.Configured); e != nil {
			return nil, e
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
func (s *Store) Delete(id, owner string, all bool) error {
	if all {
		owner = ""
	}
	r, e := s.db.Exec(`DELETE FROM datasource_sessions WHERE id=$1 AND ($2='' OR owner=$2)`, id, owner)
	if e == nil {
		if n, _ := r.RowsAffected(); n == 0 {
			return sql.ErrNoRows
		}
	}
	return e
}
func (s *Store) Test(id, owner string, all bool) (TestResult, error) {
	x, e := s.Get(id)
	if e != nil {
		return TestResult{}, e
	}
	if x.Owner != owner && !all {
		return TestResult{}, sql.ErrNoRows
	}
	supported := IsSupportedProvider(x.Provider)
	return TestResult{Provider: x.Provider, Configured: len(x.Config) > 0, Supported: supported}, nil
}
func IsNotFound(e error) bool { return errors.Is(e, sql.ErrNoRows) }
