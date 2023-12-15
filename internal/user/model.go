package user

import "time"

const (
	PlanDefault      = "free"
	ContextKeyUserId = "UserId"
)

type RegisterPayload struct {
	Name     string `json:"name" validate:"required"`
	Email    string `json:"email" validate:"email,required"`
	Password string `json:"password" validate:"gte=10,required"`
}

type LoginPayload struct {
	Email    string `json:"email" validate:"email,required"`
	Password string `json:"password" validate:"gte=10,required"`
}

type GetAccessTokenViaRefreshTokenPayload struct {
	RefreshToken string `validate:"jwt,required"`
}

type GetUserByIdPayloadToUserAPI struct {
	UserId string `json:"userId"`
}

type UpdateUserByIdPayload struct {
	Id       string `json:"id,omitempty"`
	Name     string `json:"name,omitempty" validate:"required_without_all=Email Password"`
	Email    string `json:"email,omitempty" validate:"email,required_without_all=Name Password"`
	Password string `json:"password,omitempty" validate:"gte=10,required_without_all=Name Email"`
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
