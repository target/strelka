package tosss3

import (
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

func tossS3Delete(AccessKey string, AccessSecret string, myBucket string, filename string, region string, endpoint string) {

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

	// Delete log from S3 now that it's been read
	_, err := svc.DeleteObject(&s3.DeleteObjectInput{Bucket: aws.String(string(myBucket)), Key: aws.String(filename)})
	if err != nil {
		log.Printf("Unable to delete object %q from bucket %q, %v", filename, myBucket, err)
	}

	err = svc.WaitUntilObjectNotExists(&s3.HeadObjectInput{
		Bucket: aws.String(string(myBucket)),
		Key:    aws.String(filename),
	})
	if err != nil {
		log.Printf("Failed to delete file from S3, %v", err)
	}
}
