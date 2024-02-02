package settings

// OnlyOffice contains the onlyoffice global settings of the app.
type OnlyOffice struct {
	URL          string `json:"url"`
	JWTSecret    string `json:"jwtSecret"`
	FullViewport bool   `json:"fullViewport"`
}

// OnlyOffice contains the onlyoffice public settings of the app.
// When logged in as a non-admin user, the JWTSecret should not be exposed to web client.
type OnlyOfficePublic struct {
	URL          string `json:"url"`
	FullViewport bool   `json:"fullViewport"`
}

func (o OnlyOffice) Public() OnlyOfficePublic {
	return OnlyOfficePublic{
		URL:          o.URL,
		FullViewport: o.FullViewport,
	}
}
