package cerror

import (
	"errors"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/goccy/go-json"
	"go.uber.org/zap"
)

func LambdaFunctionErrorToCerror(invokeOutput *lambda.InvokeOutput) *CustomError {
	functionError := aws.ToString(invokeOutput.FunctionError)
	if functionError != "" {
		var err error

		var functionErrorPayload *LambdaFunctionErrorPayload
		err = json.Unmarshal(invokeOutput.Payload, &functionErrorPayload)
		if err != nil {
			cerr := ErrorUnmarshalling
			cerr.LogFields = []zap.Field{
				zap.Error(err),
			}
			return cerr
		}

		lambdaErrorMessage := []byte(functionErrorPayload.ErrorMessage)
		var cerrorFromLambda *CustomError
		err = json.Unmarshal(lambdaErrorMessage, &cerrorFromLambda)
		if err != nil {
			var syntaxError *json.SyntaxError
			isSyntaxError := errors.As(err, &syntaxError)
			if isSyntaxError {
				return &CustomError{
					HttpStatusCode: http.StatusInternalServerError,
					LogMessage:     "an error occurred it is not type of cerror",
					LogSeverity:    zap.ErrorLevel,
					LogFields: []zap.Field{
						zap.String("invokeOutputPayload", string(invokeOutput.Payload)),
					},
				}
			}

			cerr := ErrorUnmarshalling
			cerr.LogFields = []zap.Field{
				zap.Error(err),
			}
			return cerr
		}

		return cerrorFromLambda
	}

	return nil
}
