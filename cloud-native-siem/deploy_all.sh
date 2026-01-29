#!/bin/bash

echo "🚀 Deploying Cloud-Native SIEM with MITRE ATT&CK Mapping"

# Step 1: Terraform deployment
echo "📦 Deploying infrastructure..."
cd terraform
terraform init
terraform apply -auto-approve
cd ..

# Step 2: Setup security services
echo "🔐 Enabling security services..."
chmod +x setup/security-services.sh
./setup/security-services.sh

# Step 3: Start Elasticsearch & Kibana
echo "📊 Starting Elastic Stack..."
docker-compose up -d

# Wait for Elasticsearch to be ready
sleep 30

# Step 4: Deploy Lambda function
echo "⚡ Deploying Lambda processor..."
cd lambda
chmod +x deploy.sh
ES_ENDPOINT="http://localhost:9200" ./deploy.sh
cd ..

# Step 5: Configure EventBridge
echo "🔗 Setting up EventBridge rules..."
aws events put-rule --cli-input-json file://eventbridge/rules.json

# Step 6: Import Kibana dashboard
echo "📈 Configuring Kibana dashboard..."
curl -X POST "localhost:5601/api/saved_objects/_import" \
  -H "kbn-xsrf: true" \
  --form file=@kibana/dashboard.ndjson

# Step 7: Test the deployment
echo "🧪 Testing deployment..."
aws lambda invoke \
  --function-name siem-security-processor \
  --payload '{"test": "event"}' \
  test-output.json

echo "✅ Deployment complete!"
echo "📊 Access Kibana at: http://localhost:5601"
echo "🔍 Access OpenCTI at: http://localhost:8080"
