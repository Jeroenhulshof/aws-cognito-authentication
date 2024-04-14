package main

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/config"
	cognito "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
)

type AwsCognitoClient struct {
	Client *cognito.Client
}

func NewAwsCognitoClient() (*AwsCognitoClient, error) {
	conf, err := config.LoadDefaultConfig(context.TODO())

	if err != nil {
		panic("Unable to load config from AWS SDK")
	}

	client := cognito.NewFromConfig(conf)

	return &AwsCognitoClient{
		Client: client,
	}, nil
}

type signUpRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func signup() {
	//awsCognitoClient, err := NewAwsCognitoClient()
	//
	//if err != nil {
	//	panic("Unable to create AWS Cognito client: " + err.Error())
	//}
}
