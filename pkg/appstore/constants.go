package appstore

const (
	FailureTypeInvalidCredentials     = "-5000"
	FailureTypePasswordTokenExpired   = "2034"
	FailureTypeLicenseNotFound        = "9610"
	FailureTypeTemporarilyUnavailable = "2059"
	FailureTypePasswordHasChanged     = "2002"

	CustomerMessageBadLogin             = "MZFinance.BadLogin.Configurator_message"
	CustomerMessageSubscriptionRequired = "Subscription Required"
	CustomerMessageAccountDisabled      = "Your account is disabled."

	iTunesAPIDomain     = "itunes.apple.com"
	iTunesAPIPathSearch = "/search"
	iTunesAPIPathLookup = "/lookup"

	PriavteAppStoreAPIDomainPrefixWithoutAuthCode = "p25"
	PriavteAppStoreAPIDomainPrefixWithAuthCode    = "p71"
	PrivateAppStoreAPIDomain                      = "buy." + iTunesAPIDomain
	PrivateAppStoreAPIPathAuthenticate            = "/WebObjects/MZFinance.woa/wa/authenticate"
	PrivateAppStoreAPIPathPurchase                = "/WebObjects/MZBuy.woa/wa/buyProduct"
	PrivateAppStoreAPIPathDownload                = "/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct"

	HTTPHeaderStoreFront = "X-Set-Apple-Store-Front"

	PricingParameterAppStore    = "STDQ"
	PricingParameterAppleArcade = "GAME"
)
