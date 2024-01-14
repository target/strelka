package tosss3

import (
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

func ListS3BucketContents(AccessKey string, AccessSecret string, myBucket string, region string, endpoint string) *s3.ListObjectsV2Output {

	// Create a Session with a custom creds
	var awsConfig = &aws.Config{
		Region:      aws.String(region),
		Endpoint:    aws.String(endpoint),
		Credentials: credentials.NewStaticCredentials(string(AccessKey), string(AccessSecret), ""),
	}

	// The session the S3 Uploader will use
	sess := session.Must(session.NewSession(awsConfig))

	// Create S3 service client
	svc := s3.New(sess)

	resp, err := svc.ListObjectsV2(&s3.ListObjectsV2Input{Bucket: aws.String(string(myBucket))})
	if err != nil {
		log.Printf("Unable to list items in bucket %q, %v", myBucket, err)
	}

	return resp
}
