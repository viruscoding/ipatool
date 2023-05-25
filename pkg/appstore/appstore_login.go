package appstore

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/99designs/keyring"
	"github.com/pkg/errors"
	"github.com/viruscoding/ipatool/pkg/http"
	"github.com/viruscoding/ipatool/pkg/util"
	"os"
	"strings"
)

type LoginAddressResult struct {
	FirstName string `plist:"firstName,omitempty"`
	LastName  string `plist:"lastName,omitempty"`
}

type LoginAccountResult struct {
	Email   string             `plist:"appleId,omitempty"`
	Address LoginAddressResult `plist:"address,omitempty"`
}

type LoginResult struct {
	FailureType         string             `plist:"failureType,omitempty"`
	CustomerMessage     string             `plist:"customerMessage,omitempty"`
	Account             LoginAccountResult `plist:"accountInfo,omitempty"`
	DirectoryServicesID string             `plist:"dsPersonId,omitempty"`
	PasswordToken       string             `plist:"passwordToken,omitempty"`
}

type LoginOutput struct {
	Name  string
	Email string
}

// LoginFirstMaybe 如果keyring中存在account则更新密码, 不存在则登录
func (a *appstore) LoginFirstMaybe(email, password string) error {
	if data, err := a.keychain.Get("account"); err != nil {
		if !errors.Is(err, keyring.ErrKeyNotFound) {
			return errors.Wrap(err, "LoginFirstMaybe")
		}
		// 登录
		login, err := a.Login(email, password, "")
		if err != nil {
			return errors.Wrap(err, "LoginFirstMaybe")
		}
		a.logger.Verbose().
			Str("email", email).
			Str("password", password).
			Str("nickname", login.Name).
			Msg("login success")
	} else { // 更新密码
		acc := Account{}
		if err := json.Unmarshal(data, &acc); err != nil {
			return errors.Wrap(err, "LoginFirstMaybe")
		}

		acc.Password = password
		if data, err = json.Marshal(acc); err != nil {
			return errors.Wrap(err, "LoginFirstMaybe")
		}

		err := a.keychain.Set("account", data)
		if err != nil {
			return errors.Wrap(err, "LoginFirstMaybe")
		}
	}
	return nil
}

func (a *appstore) Login(email, password, authCode string) (LoginOutput, error) {
	if password == "" && !a.interactive {
		return LoginOutput{}, ErrPasswordRequired
	}

	if password == "" && a.interactive {
		a.logger.Log().Msg("enter password:")

		var err error
		password, err = a.promptForPassword()
		if err != nil {
			return LoginOutput{}, errors.Wrap(err, ErrGetData.Error())
		}
	}

	macAddr, err := a.machine.MacAddress()
	if err != nil {
		return LoginOutput{}, errors.Wrap(err, ErrGetMAC.Error())
	}

	guid := strings.ReplaceAll(strings.ToUpper(macAddr), ":", "")
	a.logger.Verbose().Str("mac", macAddr).Str("guid", guid).Send()

	acc, err := a.login(email, password, authCode, guid, 0, false)
	if err != nil {
		return LoginOutput{}, errors.Wrap(err, ErrLogin.Error())
	}

	return LoginOutput{
		Name:  acc.Name,
		Email: acc.Email,
	}, nil
}

func (a *appstore) login(email, password, authCode, guid string, attempt int, failOnAuthCodeRequirement bool) (Account, error) {
	a.logger.Verbose().
		Int("attempt", attempt).
		Str("password", password).
		Str("email", email).
		Str("authCode", util.IfEmpty(authCode, "<nil>")).
		Msg("sending login request")

	request := a.loginRequest(email, password, authCode, guid)
	res, err := a.loginClient.Send(request)
	if err != nil {
		return Account{}, errors.Wrap(err, ErrRequest.Error())
	}

	if attempt == 0 && res.Data.FailureType == FailureTypeInvalidCredentials {
		return a.login(email, password, authCode, guid, 1, failOnAuthCodeRequirement)
	}

	if res.Data.FailureType != "" && res.Data.CustomerMessage != "" {
		a.logger.Verbose().Interface("response", res).Send()
		return Account{}, errors.New(res.Data.CustomerMessage)
	}

	if res.Data.FailureType != "" {
		a.logger.Verbose().Interface("response", res).Send()
		return Account{}, ErrGeneric
	}

	if res.Data.FailureType == "" && authCode == "" && res.Data.CustomerMessage == CustomerMessageBadLogin {
		if failOnAuthCodeRequirement {
			return Account{}, ErrAuthCodeRequired
		}

		if a.interactive {
			a.logger.Log().Msg("enter 2FA code:")
			authCode, err = a.promptForAuthCode()
			if err != nil {
				return Account{}, errors.Wrap(err, ErrGetData.Error())
			}

			return a.login(email, password, authCode, guid, 0, failOnAuthCodeRequirement)
		} else {
			return Account{}, ErrAuthCodeRequired
		}
	}

	if res.Data.CustomerMessage == CustomerMessageAccountDisabled {
		return Account{}, ErrAccountDisabled
	}

	if res.Data.PasswordToken == "" {
		a.logger.Verbose().Interface("response", res).Send()
		return Account{}, ErrPasswordTokenEmpty
	}

	addr := res.Data.Account.Address
	acc := Account{
		Name:                strings.Join([]string{addr.FirstName, addr.LastName}, " "),
		Email:               res.Data.Account.Email,
		PasswordToken:       res.Data.PasswordToken,
		DirectoryServicesID: res.Data.DirectoryServicesID,
		StoreFront:          res.Headers[HTTPHeaderStoreFront],
		Password:            password,
	}

	data, err := json.Marshal(acc)
	if err != nil {
		return Account{}, errors.Wrap(err, ErrMarshal.Error())
	}

	err = a.keychain.Set("account", data)
	if err != nil {
		return Account{}, errors.Wrap(err, ErrSetKeychainItem.Error())
	}

	return acc, nil
}

func (a *appstore) loginRequest(email, password, authCode, guid string) http.Request {
	attempt := "4"
	if authCode != "" {
		attempt = "2"
	}

	return http.Request{
		Method:         http.MethodPOST,
		URL:            a.authDomain(authCode, guid),
		ResponseFormat: http.ResponseFormatXML,
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
		Payload: &http.XMLPayload{
			Content: map[string]interface{}{
				"appleId":       email,
				"attempt":       attempt,
				"createSession": "true",
				"guid":          guid,
				"password":      fmt.Sprintf("%s%s", password, authCode),
				"rmp":           "0",
				"why":           "signIn",
			},
		},
	}
}

func (a *appstore) promptForAuthCode() (string, error) {
	reader := bufio.NewReader(a.ioReader)
	authCode, err := reader.ReadString('\n')
	if err != nil {
		return "", errors.Wrap(err, ErrGetData.Error())
	}

	authCode = strings.Trim(authCode, "\n")
	authCode = strings.Trim(authCode, "\r")

	return authCode, nil
}

func (*appstore) authDomain(authCode, guid string) string {
	prefix := PriavteAppStoreAPIDomainPrefixWithoutAuthCode
	if authCode != "" {
		prefix = PriavteAppStoreAPIDomainPrefixWithAuthCode
	}

	return fmt.Sprintf(
		"https://%s-%s%s?guid=%s", prefix, PrivateAppStoreAPIDomain, PrivateAppStoreAPIPathAuthenticate, guid)
}

func (a *appstore) promptForPassword() (string, error) {
	password, err := a.machine.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", errors.Wrap(err, ErrGetData.Error())
	}

	return string(password), nil
}
