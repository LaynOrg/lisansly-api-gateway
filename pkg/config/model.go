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

	EnvironmentVariableGetUserByIdFunctionName                   = "USER_API_GET_USER_BY_ID_FUNCTION_NAME"                     // #nosec G101
	EnvironmentVariableRegisterFunctionName                      = "USER_API_REGISTER_FUNCTION_NAME"                           // #nosec G101
	EnvironmentVariableLoginFunctionName                         = "USER_API_LOGIN_FUNCTION_NAME"                              // #nosec G101
	EnvironmentVariableGetAccessTokenViaRefreshTokenFunctionName = "USER_API_GET_ACCESS_TOKEN_VIA_REFRESH_TOKEN_FUNCTION_NAME" // #nosec G101
	EnvironmentVariableUpdateUserByIdFunctionName                = "USER_API_UPDATE_USER_BY_ID_FUNCTION_NAME"                  // #nosec G101

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
