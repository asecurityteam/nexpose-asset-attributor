package v1

import (
	"context"
	"fmt"
)

type GreetingInput struct {
	Pronoun string `json:"pronoun"`
	Name    string `json:"name"`
}

type GreetingOutput struct {
	Greeting string `json:"greeting"`
}

type GreetingHandler struct {
}

func (h *GreetingHandler) Handle(ctx context.Context, in GreetingInput) (GreetingOutput, error) {
	greeting := fmt.Sprintf("Hello %s!", in.Name)
	if in.Pronoun != "" {
		greeting = fmt.Sprintf("Hello %s. %s!", in.Pronoun, in.Name)
	}
	return GreetingOutput{Greeting: greeting}, nil
}
