package jwt_generator

import "github.com/golang-jwt/jwt/v4"

const (
	IssuerDefault = "lisansly"
	PlanDefault   = "free"
)

type Claims struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Plan  string `json:"plan"`
	jwt.RegisteredClaims
}

type Tokens struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken,omitempty"`
}
