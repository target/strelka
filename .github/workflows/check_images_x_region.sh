#!/bin/bash

set -e

tag=$1

timeout_seconds=120

# Use a variable because return 1 will exit the script with `set -e`, but we want to retry.
checkImageResult="false"

function checkImages() {
  repo=$1
  primary_sha=$(aws ecr describe-images --region us-east-1 --repository-name $repo --image-ids imageTag=$tag | jq -r '.imageDetails[0].imageDigest')

  for region in us-east-2 us-west-1 us-west-2 eu-west-1 eu-west-2 ca-central-1 eu-central-2; do
    sha=$(aws ecr describe-images --region $region --repository-name $repo --image-ids imageTag=$tag | jq -r '.imageDetails[0].imageDigest')

    if [[ "$sha" != "$primary_sha" ]]; then
      echo "Incomplete ECR propagation for repo $repo (tag $tag) in $region. Expected $primary_sha but found $sha."
      return 0
    fi

    echo "ECR propagation for repo $repo (tag $tag) in $region is complete. Found $sha"
  done

  checkImageResult="true"

  return 0
}

function checkImagesWithTimeout() {
  repo=$1

  end=$((SECONDS+$timeout_seconds))

  while [ $SECONDS -lt $end ]; do
      checkImageResult="false"
      checkImages $repo

      if [ "$checkImageResult" = "true" ]; then
          return 0
      fi
      echo "Replication has not finished for $repo, sleeping."
      sleep 5
  done

  echo "Replication did not finish for $repo after waiting $timeout_seconds"

  # Just exit instead of checking status codes below (although it doesn't matter with `set -e`
  exit 1
}

checkImagesWithTimeout strelka-frontend
checkImagesWithTimeout strelka-backend
checkImagesWithTimeout strelka-manager
