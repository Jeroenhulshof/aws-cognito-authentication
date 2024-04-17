package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	cognito "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"log"
	"os"
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

type CognitoEvent struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

func calculateSecretHash(clientId, clientSecret, username string) (string, error) {
	key := []byte(clientSecret)
	data := []byte(username + clientId)
	h := hmac.New(sha256.New, key)
	_, err := h.Write(data)

	if err != nil {
		return "", err
	}
	hash := h.Sum(nil)

	return base64.StdEncoding.EncodeToString(hash), nil
}

func signup(event CognitoEvent) error {
	awsCognitoClient, err := NewAwsCognitoClient()

	if err != nil {
		return fmt.Errorf("unable to create AWS Cognito client: %w", err)
	}

	secret, err := calculateSecretHash(os.Getenv("CLIENT_ID"), os.Getenv("SECRET"), event.Username)

	input := &cognito.SignUpInput{
		ClientId:   aws.String(os.Getenv("CLIENT_ID")),
		SecretHash: aws.String(secret),
		Username:   aws.String(event.Username),
		Password:   aws.String(event.Password),
		UserAttributes: []types.AttributeType{
			{
				Name:  aws.String("email"),
				Value: aws.String(event.Email),
			},
		},
	}

	_, err = awsCognitoClient.Client.SignUp(context.TODO(), input)

	if err != nil {
		return fmt.Errorf("unable to sign up user: %w", err)
	}

	return nil
}

func handler(context context.Context, event *CognitoEvent) error {
	if event == nil {
		log.Print("received nil event")

		return nil
	}

	err := signup(*event)

	if err != nil {
		log.Printf("Error signing up user: %v", err)
		return err
	}
	log.Println("User signed up successfully")

	return nil
}

func main() {
	lambda.Start(handler)
}
