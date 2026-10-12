package compose

import (
	"context"
	"fmt"

	"github.com/compose-spec/compose-go/v2/loader"
	"github.com/compose-spec/compose-go/v2/types"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const composeFilename = "compose.yaml"

// Load parses an already interpolated Compose document with the pinned
// loader (spec §20.3 step 3, ADR-0006). The loader sees one in-memory file,
// an empty environment and no resource loaders: it never reads the disk, the
// process environment or a .env file, and it resolves no include, extends,
// path or env_file.
func Load(interpolated []byte, project string) (*types.Project, error) {
	if len(interpolated) > MaxRawBytes {
		return nil, modelViolation("document", "exceeds %d bytes", MaxRawBytes)
	}
	details := types.ConfigDetails{
		WorkingDir:  "/",
		ConfigFiles: []types.ConfigFile{{Filename: composeFilename, Content: interpolated}},
		Environment: types.Mapping{},
	}
	p, err := loader.LoadWithContext(context.Background(), details, func(o *loader.Options) {
		o.SkipInterpolation = true
		o.SkipInclude = true
		o.SkipExtends = true
		o.SkipResolveEnvironment = true
		o.ResolvePaths = false
		o.SetProjectName(project, true)
	})
	if err != nil {
		return nil, smerr.Wrap(err, smerr.CodeFor(smerr.ReasonComposeRejected), smerr.ReasonComposeRejected, "compose document does not load")
	}
	return p, nil
}

// modelViolation is the single way this package reports a closed-schema violation.
func modelViolation(path, format string, args ...any) error {
	return smerr.FromReason(smerr.ReasonComposeRejected, path+": "+fmt.Sprintf(format, args...))
}
