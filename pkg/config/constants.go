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

	EnvironmentVariableGetUserByIdFunctionName                   = "USER_API_GET_USER_BY_ID_FUNCTION_NAME"
	EnvironmentVariableRegisterFunctionName                      = "USER_API_REGISTER_FUNCTION_NAME"
	EnvironmentVariableLoginFunctionName                         = "USER_API_LOGIN_FUNCTION_NAME"
	EnvironmentVariableGetAccessTokenViaRefreshTokenFunctionName = "USER_API_GET_ACCESS_TOKEN_VIA_REFRESH_TOKEN_FUNCTION_NAME"
	EnvironmentVariableUpdateUserByIdFunctionName                = "USER_API_UPDATE_USER_BY_ID_FUNCTION_NAME"

	EnvironmentVariableJwtPrivateKey = "JWT_PRIVATE_KEY"
	EnvironmentVariableJwtPublicKey  = "JWT_PUBLIC_KEY"
)
