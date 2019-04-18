package nexpose

// Link represents a hyperlink and relation
type Link struct {
	// A hypertext reference.
	Href string `json:"href,omitempty"`
	// The link relation type.
	Rel string `json:"rel,omitempty"`
}
