package tosss3

import (
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

func UploadToS3(AccessKey string, AccessSecret string, myBucket string, region string, endpoint string) {

	var filename = "/var/log/strelka/strelka.log"

	// Create a Session with a custom creds
	var awsConfig = &aws.Config{
		Region:      aws.String(region),
		Endpoint:    aws.String(endpoint),
		Credentials: credentials.NewStaticCredentials(string(AccessKey), string(AccessSecret), ""),
	}

	// The session the S3 Uploader will use
	sess := session.Must(session.NewSession(awsConfig))

	// Create an uploader with the session and custom options
	uploader := s3manager.NewUploader(sess, func(u *s3manager.Uploader) {
		u.PartSize = 5 * 1024 * 1024 // The minimum/default allowed part size is 5MB
		u.Concurrency = 2            // default is 5
	})

	// Prune old logs before adding new ones...
	tossS3PruneLogs(AccessKey, AccessSecret, myBucket, region, endpoint)

	var fileKey = "strelka" + time.Now().Format("2006-01-02T15") + ".log"

	// Check to see if we're going to make a new file to see if we should truncate local log file for hour chunks

	var bucketContents = ListS3BucketContents(AccessKey, AccessSecret, myBucket, region, endpoint)
	var logExists bool = false

	for _, item := range bucketContents.Contents {
		if strings.Compare(*item.Key, fileKey) == 0 {
			logExists = true
		}
	}

	// If file already exists in s3 continue with upload or leave to be pruned out later
	if !logExists {
		//If log doesn't exist, that means we're about to create a new s3 log, so truncate local strelka.log file
		err := os.Truncate("/var/log/strelka/strelka.log", 0)
		if err != nil {
			log.Printf("Failed to truncate strelka.log file at time of log rotation: %v", err)
		}
	}

	// Open the file
	f, err := os.Open(filename)
	if err != nil {
		log.Printf("failed to open file %q, %v", filename, err)
		return
	}

	// Upload the file to S3.
	result, err := uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(string(myBucket)),
		Key:    aws.String(fileKey),
		Body:   f,
	})

	// In case it fails to upload
	if err != nil {
		log.Printf("Failed to upload file, %v", err)
		return
	} else {
		log.Printf("file uploaded to, %s\n", result.Location)
	}
}
