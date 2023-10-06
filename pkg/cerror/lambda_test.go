package cerror

import (
	"net/http"
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalLambdaFunctionErrorToCerror(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		cerr := &CustomError{
			HttpStatusCode: http.StatusConflict,
		}
		marshalledCerr, err := json.Marshal(cerr)
		require.NoError(t, err)

		lambdaCerrPayload, err := json.Marshal(&LambdaFunctionErrorPayload{
			ErrorMessage: string(marshalledCerr),
			ErrorType:    ErrorTypeUnhandled,
		})
		require.NoError(t, err)

		unmarshalledCerr, err := UnmarshalLambdaFunctionErrorToCerror(lambdaCerrPayload)

		assert.NoError(t, err)
		assert.Equal(t, cerr, unmarshalledCerr)
	})

	t.Run("ambiguous lambda error payload", func(t *testing.T) {
		unmarshalledCerr, err := UnmarshalLambdaFunctionErrorToCerror([]byte(`{"key":"value"}`))

		assert.Error(t, err)
		assert.Nil(t, unmarshalledCerr)
	})

	t.Run("ambiguous cerror payload", func(t *testing.T) {
		lambdaCerrPayload, err := json.Marshal(&LambdaFunctionErrorPayload{
			ErrorMessage: `{"key":"value"`,
			ErrorType:    ErrorTypeUnhandled,
		})
		require.NoError(t, err)

		unmarshalledCerr, err := UnmarshalLambdaFunctionErrorToCerror(lambdaCerrPayload)

		assert.Error(t, err)
		assert.Nil(t, unmarshalledCerr)
	})
}
