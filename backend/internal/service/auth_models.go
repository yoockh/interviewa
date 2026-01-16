package service

type RegisterInput struct {
	Email    string
	Password string
}

type LoginInput struct {
	Email      string
	Password   string
	DeviceID   string
	DeviceName string
	IPAddress  *string
	UserAgent  *string
}

type LoginMFAInput struct {
	MFAToken   string
	Code       string
	DeviceID   string
	DeviceName string
	IPAddress  *string
	UserAgent  *string
}

type LoginResult struct {
	AccessToken       string
	ExpiresIn         int64
	RefreshToken      string
	RefreshExpiresIn  int64
	MFARequired       bool
	MFAToken          string
	MFATokenExpiresIn int64
}
