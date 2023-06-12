//go:build unit

package path

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Path(t *testing.T) {
	t.Run("should return base path of path", func(t *testing.T) {
		rootDirectory := GetRootDirectory()

		assert.Regexp(t, "/api-gateway", rootDirectory)
	})
}
