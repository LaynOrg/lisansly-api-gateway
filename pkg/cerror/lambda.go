package cerror

import (
	"github.com/goccy/go-json"
	"go.uber.org/zap"
)

func UnmarshalLambdaFunctionErrorToCerror(lambdaFunctionErrorPayload []byte) (*CustomError, error) {
	var err error

	var functionErrorPayload LambdaFunctionErrorPayload
	err = json.Unmarshal(lambdaFunctionErrorPayload, &functionErrorPayload)
	if err != nil {
		cerr := ErrorUnmarshalling
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerr
	}

	lambdaErrorMessage := []byte(functionErrorPayload.ErrorMessage)

	var cerrorFromLambda *CustomError
	err = json.Unmarshal(lambdaErrorMessage, &cerrorFromLambda)
	if err != nil {
		cerr := ErrorUnmarshalling
		cerr.LogFields = []zap.Field{
			zap.Error(err),
		}
		return nil, cerr
	}

	return cerrorFromLambda, nil
}
