package nexpose

// Configuration represents a name-value pair
type Configuration struct {
	// The name of the configuration value.
	Name string `json:"name"`
	// The configuration value.
	Value string `json:"value,omitempty"`
}
