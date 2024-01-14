package tosss3

import (
	"log"
	"math"
	"strings"
	"time"
)

func tossS3PruneLogs(AccessKey string, AccessSecret string, myBucket string, region string, endpoint string) {

	layout := "2006-01-02T15"
	var bucketContents = ListS3BucketContents(AccessKey, AccessSecret, myBucket, region, endpoint)

	for _, item := range bucketContents.Contents {

		s3logTimstampRaw := strings.Trim(*item.Key, "strelka.log")
		s3logTimstamp, err := time.Parse(layout, s3logTimstampRaw)

		if err != nil {
			log.Println(err)
		}

		// Check to see if its from same date as current date, otherwise throw it out
		y1, m1, d1 := time.Now().Date()
		y2, m2, d2 := s3logTimstamp.Date()

		if y1 == y2 && m1 == m2 && d1 == d2 {
			// Same day, Check to see how many hours its been ...
			diffTime := time.Now().Sub(s3logTimstamp).Hours()
			hs, _ := math.Modf(diffTime)
			if hs > 1 {
				// Old log, delete it
				log.Println("Difference between hours is greater than 1, deleting old log file")
				tossS3Delete(AccessKey, AccessSecret, myBucket, *item.Key, region, endpoint)
			}

		} else {
			// Delete the old log
			tossS3Delete(AccessKey, AccessSecret, myBucket, *item.Key, region, endpoint)
		}

	}
}
