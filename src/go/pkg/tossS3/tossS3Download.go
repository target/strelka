package tosss3

import (
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

func DownloadFromS3(AccessKey string, AccessSecret string, myBucket string, filename string, region string, endpoint string) []byte {

	// Create a Session with a custom creds
	var awsConfig = &aws.Config{
		Region:      aws.String(region),
		Endpoint:    aws.String(endpoint),
		Credentials: credentials.NewStaticCredentials(string(AccessKey), string(AccessSecret), ""),
	}

	// The session the S3 Uploader will use
	sess := session.Must(session.NewSession(awsConfig))

	// Create downloader in order to retrieve log files (Should hopefully only be one)
	downloader := s3manager.NewDownloader(sess)

	// Prune out old logs before downloading to reduce time to catch up
	tossS3PruneLogs(AccessKey, AccessSecret, myBucket, region, endpoint)

	buff := &aws.WriteAtBuffer{}

	// Iterate through buckets, download to buffer
	logFileFromS3, err := downloader.Download(buff, &s3.GetObjectInput{
		Bucket: aws.String(string(myBucket)),
		Key:    aws.String(filename),
	})
	if err != nil {
		log.Printf("failed to download file, %v", err)
	}
	log.Printf("Persistance log downloaded from S3, %d bytes\n", logFileFromS3)

	tossS3Delete(AccessKey, AccessSecret, myBucket, filename, region, endpoint)

	return buff.Bytes()
}
