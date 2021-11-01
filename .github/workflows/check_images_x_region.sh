#!/bin/bash

set -e

tag=$1

function checkImages() {
  repo=$1
  primary_sha=$(aws ecr describe-images --region us-east-1 --repository-name $repo --image-ids imageTag=$tag | jq -r '.imageDetails[0].imageDigest')

  for region in us-east-2 us-west-1 us-west-2 eu-west-1 eu-west-2; do
    sha=$(aws ecr describe-images --region $region --repository-name $repo --image-ids imageTag=$tag | jq -r '.imageDetails[0].imageDigest')

    if [[ "$sha" != "$primary_sha" ]]; then
      echo "Incomplete ECR propagation for repo $repo (tag $tag) in $region. Expected $primary_sha but found $sha."
      exit 1
    fi
  done
}

checkImages strelka-frontend
checkImages strelka-backend
checkImages strelka-manager
checkImages strelka-mmrpc