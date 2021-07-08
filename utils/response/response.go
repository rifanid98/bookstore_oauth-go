package response

import "net/http"

type RestErr struct {
	StatusCode int16  `json:"statusCode"`
	Message    string `json:"message"`
	Error      string `json:"error"`
}

type RestResp struct {
	StatusCode int16       `json:"statusCode"`
	Message    string      `json:"message"`
	Data       interface{} `json:"data"`
}

func BadRequest(error string) *RestErr {
	return &RestErr{
		StatusCode: http.StatusBadRequest,
		Message:    http.StatusText(http.StatusBadRequest),
		Error:      error,
	}
}

func Unauthorized(error string) *RestErr {
	return &RestErr{
		StatusCode: http.StatusUnauthorized,
		Message:    http.StatusText(http.StatusUnauthorized),
		Error:      error,
	}
}

func NotImplemented(error string) *RestErr {
	return &RestErr{
		StatusCode: http.StatusNotImplemented,
		Message:    http.StatusText(http.StatusNotImplemented),
		Error:      error,
	}
}

func NotFound(error string) *RestErr {
	return &RestErr{
		StatusCode: http.StatusNotFound,
		Message:    http.StatusText(http.StatusNotFound),
		Error:      error,
	}
}

func InternalServerError(error string) *RestErr {
	return &RestErr{
		StatusCode: http.StatusInternalServerError,
		Message:    http.StatusText(http.StatusInternalServerError),
		Error:      error,
	}
}

func Success(data interface{}) *RestResp {
	return &RestResp{
		StatusCode: http.StatusOK,
		Message:    http.StatusText(http.StatusOK),
		Data:       data,
	}
}

func Created(data interface{}) *RestResp {
	return &RestResp{
		StatusCode: http.StatusCreated,
		Message:    http.StatusText(http.StatusCreated),
		Data:       data,
	}
}
