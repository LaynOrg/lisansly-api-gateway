package config

type FunctionNames struct {
	UserAPI map[UserApiFunctionNames]string
}

type JwtConfig struct {
	PrivateKey []byte
	PublicKey  []byte
}
