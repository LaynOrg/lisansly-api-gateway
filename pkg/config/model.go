package config

type UserApiFunctionNames string

const (
	GetUserById                   UserApiFunctionNames = "GetUserById"
	Register                      UserApiFunctionNames = "Register"
	Login                         UserApiFunctionNames = "Login"
	GetAccessTokenViaRefreshToken UserApiFunctionNames = "GetAccessTokenViaRefreshToken"
	UpdateUserById                UserApiFunctionNames = "UpdateUserById"
)

// #nosec
const (
	EnvironmentVariableNotDefined = "%s variable is not defined"

	EnvironmentVariableGetUserByIdFunctionName                  = "USER_SERVICE_GET_USER_BY_ID_FUNCTION_NAME"                    // #nosec G101
	EnvironmentVariableRegisterFunctionName                     = "USER_SERVICE_REGISTER_FUNCTION_NAME"                          // #nosec G101
	EnvironmentVariableLoginFunctionName                        = "USER_SERVICE_LOGIN_FUNCTION_NAME"                             // #nosec G101
	EnvironmentVariableGetAccessTokenByRefreshTokenFunctionName = "USER_SERVICE_GET_ACCESS_TOKEN_BY_REFRESH_TOKEN_FUNCTION_NAME" // #nosec G101
	EnvironmentVariableUpdateUserByIdFunctionName               = "USER_SERVICE_UPDATE_USER_BY_ID_FUNCTION_NAME"                 // #nosec G101

	EnvironmentVariableJwtPrivateKey = "JWT_PRIVATE_KEY" // #nosec G101
	EnvironmentVariableJwtPublicKey  = "JWT_PUBLIC_KEY"  // #nosec G101
)

type FunctionNames struct {
	UserAPI map[UserApiFunctionNames]string
}

type JwtConfig struct {
	PrivateKey []byte
	PublicKey  []byte
}
