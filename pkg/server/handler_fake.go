package server

import "github.com/gofiber/fiber/v2"

type fakeHandler struct {
}

type FakeHandler interface {
	Handler
}

func NewFakeHandler() FakeHandler {
	return &fakeHandler{}
}

func (f *fakeHandler) RegisterRoutes(app *fiber.App) {
	app.Get("/fake", nil)
}
