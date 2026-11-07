package release

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func safeDir(path string, create bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("managed path must be clean and absolute")
	}
	for p := path; ; p = filepath.Dir(p) {
		s, e := os.Lstat(p)
		if e == nil && (!s.IsDir() || s.Mode()&os.ModeSymlink != 0) {
			return errors.New("managed path contains non-directory or symbolic link")
		}
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	if create {
		return os.MkdirAll(path, 0700)
	}
	return nil
}
func readRegular(path string) ([]byte, error) {
	s, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !s.Mode().IsRegular() || s.Size() > 8<<20 {
		return nil, errors.New("unsafe or oversized managed file")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 8<<20))
}
func readJSON(path string, value any) error {
	b, e := readRegular(path)
	if e != nil {
		return e
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if e = d.Decode(value); e != nil {
		return errors.New("invalid managed JSON")
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("multiple JSON values")
	}
	return nil
}
func writeFile(path string, b []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, e := os.CreateTemp(dir, ".lineops-pending-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(mode); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(f.Name(), path); e != nil {
		return e
	}
	return syncDir(dir)
}
func writeJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return writeFile(path, b, 0600)
}
func switchCurrent(dir, version string) error {
	if !identifier.MatchString(version) {
		return errors.New("invalid version reference")
	}
	target := "versions/" + version
	// A task-specific new symlink is never followed. Rename is atomic on the same filesystem.
	name := filepath.Join(dir, ".current-next")
	if s, e := os.Lstat(name); e == nil {
		if s.Mode()&os.ModeSymlink == 0 {
			return errors.New("unexpected current staging file")
		}
		if e = os.Remove(name); e != nil {
			return e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e := os.Symlink(target, name); e != nil {
		return e
	}
	if e := os.Rename(name, filepath.Join(dir, "current")); e != nil {
		return e
	}
	return syncDir(dir)
}

type Manifest struct {
	Version string            `json:"version"`
	Files   map[string]string `json:"files"`
}

func freezeVersion(dir, name string, desired, effective Model, certs []Certificate, renderedConfig ...[]byte) (Manifest, error) {
	vdir := filepath.Join(dir, "versions", name)
	if _, e := os.Lstat(vdir); !errors.Is(e, os.ErrNotExist) {
		return Manifest{}, errors.New("immutable version already exists")
	}
	if e := os.Mkdir(vdir, 0700); e != nil {
		return Manifest{}, e
	}
	files := map[string][]byte{}
	var e error
	if len(renderedConfig) > 0 && len(renderedConfig[0]) > 0 {
		materialized := strings.ReplaceAll(string(renderedConfig[0]), PortableVersionDir, filepath.ToSlash(vdir))
		files["config.json"] = []byte(materialized)
		files["rendered.json"] = renderedConfig[0]
	} else {
		files["config.json"], e = Render(effective, vdir)
		if e != nil {
			return Manifest{}, e
		}
	}
	var runtime RuntimeConfig
	if err := readJSON(filepath.Join(dir, "runtime.json"), &runtime); err == nil && runtime.TrafficAPI {
		files["config.json"], e = addTrafficAPI(files["config.json"], runtime.InstanceID, effective)
		if e != nil {
			return Manifest{}, e
		}
	}
	files["desired.json"], _ = json.Marshal(desired)
	files["model.json"], _ = json.Marshal(effective)
	for _, c := range certs {
		files["tls-"+c.ID+".pem"] = c.CertificatePEM
		files["key-"+c.ID+".pem"] = c.PrivateKeyPEM
		files["trust-"+c.ID+".pem"] = c.TrustPEM
	}
	manifest := Manifest{Version: name, Files: map[string]string{}}
	for name, b := range files {
		if e = writeFile(filepath.Join(vdir, name), b, 0400); e != nil {
			return manifest, e
		}
		manifest.Files[name] = digest(b)
	}
	if e = writeJSON(filepath.Join(vdir, "manifest.json"), manifest); e != nil {
		return manifest, e
	}
	if e = os.Chmod(filepath.Join(vdir, "manifest.json"), 0400); e != nil {
		return manifest, e
	}
	if e = syncDir(vdir); e != nil {
		return manifest, e
	}
	return manifest, syncDir(filepath.Join(dir, "versions"))
}
func verifyVersion(dir, name string) (Model, Model, error) {
	var m, desired Model
	if !identifier.MatchString(name) {
		return m, desired, errors.New("invalid version ID")
	}
	vdir := filepath.Join(dir, "versions", name)
	if e := safeDir(vdir, false); e != nil {
		return m, desired, e
	}
	var manifest Manifest
	if e := readJSON(filepath.Join(vdir, "manifest.json"), &manifest); e != nil {
		return m, desired, e
	}
	if manifest.Version != name {
		return m, desired, errors.New("version mismatch")
	}
	for name, h := range manifest.Files {
		if filepath.Base(name) != name || strings.ContainsAny(name, "/\\") {
			return m, desired, errors.New("dependency path rejected")
		}
		b, e := readRegular(filepath.Join(vdir, name))
		if e != nil || digest(b) != h {
			return m, desired, errors.New("configuration or dependency drift")
		}
	}
	for _, key := range []string{"config.json", "model.json", "desired.json"} {
		if manifest.Files[key] == "" {
			return m, desired, errors.New("incomplete immutable manifest")
		}
	}
	if e := readJSON(filepath.Join(vdir, "model.json"), &m); e != nil {
		return m, desired, e
	}
	e := readJSON(filepath.Join(vdir, "desired.json"), &desired)
	return m, desired, e
}
