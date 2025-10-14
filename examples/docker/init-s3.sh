#!/bin/bash

# Wait for LocalStack to be ready (check for S3 availability using awslocal)
until awslocal --endpoint-url=http://localstack:4566 s3 ls > /dev/null 2>&1; do
  echo "Waiting for LocalStack S3 to start..."
  sleep 1
done

echo "LocalStack S3 is ready. Creating bucket..."
awslocal --endpoint-url=http://localstack:4566 s3 mb s3://bundles

