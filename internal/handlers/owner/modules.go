package owner

import (
	"context"
	"fmt"
	"iter"
	"log"
	"os"
	"path"
	"slices"

	"github.com/fido-device-onboard/go-fdo/fsim"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

type ownerModule struct {
	Name string
	Impl serviceinfo.OwnerModule
	Next func() (string, serviceinfo.OwnerModule, bool)
	Stop func()
}

func (o Owner) Module(ctx context.Context) (string, serviceinfo.OwnerModule, error) {
	token, ok := o.State.TokenFromContext(ctx)
	if !ok {
		return "", nil, fmt.Errorf("invalid context: no token")
	}
	module, ok := o.OwnerModuleStateMachine[token]
	if !ok {
		return "", nil, fmt.Errorf("NextModule not called")
	}
	return module.Name, module.Impl, nil
}

func (o Owner) NextModule(ctx context.Context) (bool, error) {
	token, ok := o.State.TokenFromContext(ctx)
	if !ok {
		return false, fmt.Errorf("invalid context: no token")
	}
	module, ok := o.OwnerModuleStateMachine[token]
	if !ok {
		// Create a new module state machine
		_, modules, _, err := o.State.Devmod(ctx)
		if err != nil {
			return false, fmt.Errorf("error getting devmod: %w", err)
		}
		next, stop := iter.Pull2(o.ownerModules(modules))
		module = &ownerModule{
			Next: next,
			Stop: stop,
		}
		o.OwnerModuleStateMachine[token] = module
	}

	var valid bool
	module.Name, module.Impl, valid = module.Next()
	return valid, nil
}

func (o Owner) CleanupModules(ctx context.Context) {
	token, ok := o.State.TokenFromContext(ctx)
	if !ok {
		return
	}
	module, ok := o.OwnerModuleStateMachine[token]
	if !ok {
		return
	}
	module.Stop()
	delete(o.OwnerModuleStateMachine, token)
}

func (o *Owner) ownerModules(modules []string) iter.Seq2[string, serviceinfo.OwnerModule] { //nolint:gocyclo
	return func(yield func(string, serviceinfo.OwnerModule) bool) {
		if slices.Contains(modules, "fdo.download") {
			for i, cleanPath := range o.downloadPaths {
				f, err := os.Open(cleanPath)
				if err != nil {
					log.Fatalf("error opening %q for download FSIM: %v", cleanPath, err)
				}
				defer func() { _ = f.Close() }()

				if !yield("fdo.download", &fsim.DownloadContents[*os.File]{
					Name:         o.downloads[i], // Use original name for display
					Contents:     f,
					MustDownload: true,
				}) {
					return
				}
			}
		}

		if slices.Contains(modules, "fdo.upload") {
			for _, name := range o.uploads {
				if !yield("fdo.upload", &fsim.UploadRequest{
					Dir:  o.uploadDir,
					Name: name,
					CreateTemp: func() (*os.File, error) {
						return os.CreateTemp(o.uploadDir, ".fdo-upload_*")
					},
				}) {
					return
				}
			}
		}

		if slices.Contains(modules, "fdo.wget") {
			for _, url := range o.wgetURLs {
				if !yield("fdo.wget", &fsim.WgetCommand{
					Name: path.Base(url.Path),
					URL:  url,
				}) {
					return
				}
			}
		}
	}
}
