package playbook

import (
	"embed"
	"fmt"
	"io/fs"
)

//go:embed presets/*.yaml
var presetFS embed.FS

// EmbeddedPresets returns the playbooks compiled into core. Hosts can expose
// these without shipping a config directory next to the binary.
func EmbeddedPresets() (map[string]*Playbook, []error) {
	out := map[string]*Playbook{}
	var errs []error
	err := fs.WalkDir(presetFS, "presets", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, rerr := presetFS.ReadFile(path)
		if rerr != nil {
			errs = append(errs, fmt.Errorf("读取 %s: %w", path, rerr))
			return nil
		}
		pb, perr := LoadPlaybookFromBytes(data)
		if perr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, perr))
			return nil
		}
		if _, dup := out[pb.ID]; dup {
			errs = append(errs, fmt.Errorf("%s: id %q 重复", path, pb.ID))
			return nil
		}
		out[pb.ID] = pb
		return nil
	})
	if err != nil {
		errs = append(errs, err)
	}
	return out, errs
}
