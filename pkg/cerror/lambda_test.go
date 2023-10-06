package cerror

import (
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLambdaFunctionErrorToCerror(t *testing.T) {
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

		unmarshalledCerr := LambdaFunctionErrorToCerror(&lambda.InvokeOutput{
			FunctionError: aws.String(ErrorTypeUnhandled),
			Payload:       lambdaCerrPayload,
			StatusCode:    http.StatusOK,
		})

		assert.Equal(t, cerr, unmarshalledCerr)
	})

	t.Run("aws function error is nil", func(t *testing.T) {
		unmarshalledCerr := LambdaFunctionErrorToCerror(&lambda.InvokeOutput{
			StatusCode: http.StatusOK,
		})

		assert.Nil(t, unmarshalledCerr)
	})

	t.Run("lambda error payload", func(t *testing.T) {
		unmarshalledCerr := LambdaFunctionErrorToCerror(&lambda.InvokeOutput{
			FunctionError: aws.String(ErrorTypeUnhandled),
			Payload:       []byte(`{"key":"value"}`),
			StatusCode:    http.StatusOK,
		})

		assert.Error(t, unmarshalledCerr)
	})

	t.Run("ambiguous cerror payload", func(t *testing.T) {
		functionErrorPayload, err := json.Marshal(&LambdaFunctionErrorPayload{
			ErrorMessage: `{"key"}`,
			ErrorType:    ErrorTypeUnhandled,
		})
		require.NoError(t, err)

		lambdaCerrPayload, err := json.Marshal(&lambda.InvokeOutput{
			FunctionError: aws.String(ErrorTypeUnhandled),
			Payload:       functionErrorPayload,
			StatusCode:    http.StatusOK,
		})
		require.NoError(t, err)

		unmarshalledCerr := LambdaFunctionErrorToCerror(&lambda.InvokeOutput{
			FunctionError: aws.String(ErrorTypeUnhandled),
			Payload:       lambdaCerrPayload,
			StatusCode:    http.StatusOK,
		})

		assert.Error(t, unmarshalledCerr)
	})
}
