package user

import "time"

const (
	PlanDefault      = "free"
	ContextKeyUserId = "UserId"
)

type RegisterPayload struct {
	Name     string `json:"name" validate:"required"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,gte=10"`
}

type LoginPayload struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,gte=10"`
}

type GetAccessTokenByRefreshTokenPayload struct {
	RefreshToken string `validate:"jwt,required"`
}

type GetUserByIdPayloadToUserAPI struct {
	UserId string `json:"userId"`
}

type UpdateUserByIdPayload struct {
	Id       string `json:"id,omitempty"`
	Name     string `json:"name,omitempty" validate:"required_without_all=Email Password,omitempty"`
	Email    string `json:"email,omitempty" validate:"required_without_all=Name Password,omitempty,email"`
	Password string `json:"password,omitempty" validate:"required_without_all=Name Email,omitempty,gte=10"`
}

type Document struct {
	Id        string    `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	Password  string    `json:"password"`
	Plan      string    `json:"plan"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt,omitempty"`
	DeletedAt time.Time `json:"deletedAt,omitempty"`
}
