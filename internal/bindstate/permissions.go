package bindstate

import (
	"errors"
	"io/fs"
	"os"
	"runtime"
)

func checkPrivateFileMode(info fs.FileInfo) error {
	// Windows uses ACLs; FileMode does not accurately represent them.  On Unix,
	// the service group may read credentials, but it must never write them and
	// no permission is granted to other users.
	permission := info.Mode().Perm()
	if runtime.GOOS != "windows" && (permission&0o400 == 0 || permission&^os.FileMode(0o640) != 0) {
		return errors.New("binding state file must be owner-readable and at most group-readable")
	}
	return nil
}
