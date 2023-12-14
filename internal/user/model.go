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

type GetAccessTokenViaRefreshTokenPayload struct {
	RefreshToken string `validate:"required,jwt"`
}

type GetUserByIdPayloadToUserAPI struct {
	UserId string `json:"userId"`
}

type UpdateUserByIdPayload struct {
	Id       string `json:"userId,omitempty"`
	Name     string `json:"name,omitempty" validate:"required_without_all=Email Password"`
	Email    string `json:"email,omitempty" validate:"required_without_all=Name Password,email"`
	Password string `json:"password,omitempty" validate:"required_without_all=Name Email,gte=10"`
}

type Document struct {
	Id        string    `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	Password  string    `json:"password"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt,omitempty"`
	DeletedAt time.Time `json:"deletedAt,omitempty"`
}
