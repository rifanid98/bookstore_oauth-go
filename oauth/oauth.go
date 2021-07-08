package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mercadolibre/golang-restclient/rest"
	resp "github.com/rifanid98/bookstore_oauth-go/utils/response"
)

const (
	HeaderXPublic   = "X-Public"
	HeaderXClientId = "X-Client-Id"
	HeaderXCallerId = "X-Caller-Id"

	paramTokenId = "token_id"
)

var (
	BaseUrl         = "http://localhost:8001"
	oauthRestClient = rest.RequestBuilder{
		BaseURL: BaseUrl,
		Timeout: 200 * time.Millisecond,
	}
)

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"user_id"`
	ClientId int64  `json:"client_id"`
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}

	return request.Header.Get(HeaderXPublic) == "true"
}

func GetCallerId(request *http.Request) int64 {
	if request == nil {
		return 0
	}

	callerId, err := strconv.ParseInt(request.Header.Get(HeaderXCallerId), 10, 64)
	if err != nil {
		return 0
	}

	return callerId
}

func GetClientId(request *http.Request) int64 {
	if request == nil {
		return 0
	}

	clientId, err := strconv.ParseInt(request.Header.Get(HeaderXClientId), 10, 64)
	if err != nil {
		return 0
	}

	return clientId
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}

	request.Header.Del(HeaderXClientId)
	request.Header.Del(HeaderXCallerId)
}

func AuthenticateRequest(request *http.Request) *resp.RestErr {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	tokenId := strings.TrimSpace(request.URL.Query().Get(paramTokenId))
	if len(tokenId) < 1 {
		return nil
	}

	at, err := getAccessToken(tokenId)
	if err != nil {
		if err.StatusCode == http.StatusNotFound {
			return nil
		}
		return err
	}

	request.Header.Add(HeaderXClientId, fmt.Sprintf("%v", at.UserId))
	request.Header.Add(HeaderXCallerId, fmt.Sprintf("%v", at.UserId))

	return nil
}

func getAccessToken(tokenId string) (*accessToken, *resp.RestErr) {
	res := oauthRestClient.Get(fmt.Sprintf("/oauth/token/%s", tokenId))
	if res == nil || res.Response == nil {
		return nil, resp.InternalServerError("failed to get tokenId")
	}

	if res.StatusCode > 299 {
		var restErr *resp.RestErr
		err := json.Unmarshal(res.Bytes(), &restErr)
		if err != nil {
			return nil, resp.InternalServerError("failed to parse data response from endpoint")
		}
		return nil, restErr
	}

	var restRes struct {
		Data *accessToken
	}
	if err := json.Unmarshal(res.Bytes(), &restRes); err != nil {
		fmt.Println(err.Error())
		return nil, resp.InternalServerError("failed to parse access token data")
	}

	return restRes.Data, nil
}
