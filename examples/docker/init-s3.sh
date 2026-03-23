#!/bin/sh

# Wait for s3proxy to be ready
until curl -sf http://s3proxy:80/ > /dev/null 2>&1; do
  echo "Waiting for s3proxy to start..."
  sleep 1
done

echo "s3proxy is ready. Creating bucket..."
curl -sf --request PUT http://s3proxy:80/bundles
echo "done"

sleep infinity
