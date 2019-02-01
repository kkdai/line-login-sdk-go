package apiservice

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

type ErrorResponse struct {
	Err       error
	ErrorCode int
}

const (
	StreamContent string = "application/octet-stream"
	JsonContent   string = "application/json"
)

//Client:
type Client struct {
	key string
}

//NewClient: New oxford client based on key
func NewClient(key string) *Client {
	c := new(Client)
	c.key = key

	return c
}

//Connect :with API url and data, return response byte or error if http.Status is not OK
func (c *Client) Connect(mode string, inUrl string, data *bytes.Buffer, useJson bool) ([]byte, *ErrorResponse) {
	client := &http.Client{}
	fmt.Println("connected: ", mode, inUrl, data)

	r := &http.Request{}
	if data == nil {
		r, _ = http.NewRequest(mode, inUrl, nil)

	} else {
		r, _ = http.NewRequest(mode, inUrl, data)
	}

	if useJson {
		r.Header.Add("Content-Type", JsonContent)
	} else {
		r.Header.Add("Content-Type", StreamContent)
	}

	r.Header.Add("Ocp-Apim-Subscription-Key", c.key)
	ret := new(ErrorResponse)
	resp, err := client.Do(r)

	if err != nil {
		log.Println("er:", err)
		ret.Err = err
		return nil, ret
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("er:", err)
		ret.Err = err
		return nil, ret
	}

	if resp.StatusCode > http.StatusAccepted {
		ret.ErrorCode = resp.StatusCode
		ret.Err = errors.New("Error on:" + string(body))
		log.Println("Error happen! body:", string(body))
		return body, ret
	}

	return body, nil
}
