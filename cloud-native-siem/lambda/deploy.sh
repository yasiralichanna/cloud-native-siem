#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🚀 Deploying Cloud-Native SIEM Lambda Function${NC}"

# Get AWS Account ID
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region)
REGION=${REGION:-us-east-1}

echo -e "${YELLOW}AWS Account: ${ACCOUNT_ID}${NC}"
echo -e "${YELLOW}AWS Region: ${REGION}${NC}"

# Create deployment package
echo -e "${YELLOW}Creating deployment package...${NC}"
cd lambda

# Clean up previous packages
rm -rf package siem-processor.zip

# Create package directory
mkdir -p package

# Install dependencies
pip install -r requirements.txt -t package/

# Copy Lambda function
cp security_processor.py package/
cp requirements.txt package/

# Create ZIP package
cd package
zip -r ../siem-processor.zip .
cd ..

# Get Elasticsearch endpoint
read -p "Enter Elasticsearch endpoint [http://localhost:9200]: " ES_ENDPOINT
ES_ENDPOINT=${ES_ENDPOINT:-http://localhost:9200}

read -p "Enter OpenCTI URL [http://localhost:8080]: " OPENCTI_URL
OPENCTI_URL=${OPENCTI_URL:-http://localhost:8080}

read -p "Enter OpenCTI Token (press enter if none): " OPENCTI_TOKEN

# Create/update Lambda function
FUNCTION_NAME="cloud-native-siem-processor"

echo -e "${YELLOW}Deploying Lambda function: ${FUNCTION_NAME}${NC}"

# Check if function exists
aws lambda get-function --function-name $FUNCTION_NAME > /dev/null 2>&1

if [ $? -eq 0 ]; then
    echo -e "${YELLOW}Updating existing Lambda function...${NC}"
    aws lambda update-function-code \
        --function-name $FUNCTION_NAME \
        --zip-file fileb://siem-processor.zip \
        --region $REGION
    
    aws lambda update-function-configuration \
        --function-name $FUNCTION_NAME \
        --environment "Variables={ES_ENDPOINT=$ES_ENDPOINT,OPENCTI_URL=$OPENCTI_URL,OPENCTI_TOKEN=$OPENCTI_TOKEN,ENVIRONMENT=development}" \
        --region $REGION \
        --timeout 30 \
        --memory-size 512
else
    echo -e "${YELLOW}Creating new Lambda function...${NC}"
    
    # Create IAM role if it doesn't exist
    ROLE_NAME="siem-lambda-execution-role"
    aws iam get-role --role-name $ROLE_NAME > /dev/null 2>&1
    
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}Creating IAM role...${NC}"
        
        # Create trust policy
        cat > trust-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "lambda.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
EOF
        
        aws iam create-role \
            --role-name $ROLE_NAME \
            --assume-role-policy-document file://trust-policy.json \
            --description "Role for Cloud-Native SIEM Lambda function"
        
        # Attach policies
        aws iam attach-role-policy \
            --role-name $ROLE_NAME \
            --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
        
        # Create custom policy
        cat > siem-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "securityhub:*",
                "cloudtrail:LookupEvents",
                "guardduty:*",
                "events:*",
                "s3:*",
                "logs:*",
                "ec2:*",
                "iam:*",
                "ssm:*",
                "sns:*",
                "kms:*"
            ],
            "Resource": "*"
        }
    ]
}
EOF
        
        aws iam put-role-policy \
            --role-name $ROLE_NAME \
            --policy-name siem-lambda-policy \
            --policy-document file://siem-policy.json
        
        rm -f trust-policy.json siem-policy.json
    fi
    
    ROLE_ARN=$(aws iam get-role --role-name $ROLE_NAME --query Role.Arn --output text)
    
    # Create Lambda function
    aws lambda create-function \
        --function-name $FUNCTION_NAME \
        --runtime python3.9 \
        --role $ROLE_ARN \
        --handler security_processor.lambda_handler \
        --zip-file fileb://siem-processor.zip \
        --environment "Variables={ES_ENDPOINT=$ES_ENDPOINT,OPENCTI_URL=$OPENCTI_URL,OPENCTI_TOKEN=$OPENCTI_TOKEN,ENVIRONMENT=development}" \
        --timeout 30 \
        --memory-size 512 \
        --region $REGION
fi

# Create EventBridge rule if it doesn't exist
RULE_NAME="securityhub-to-siem"
aws events describe-rule --name $RULE_NAME --region $REGION > /dev/null 2>&1

if [ $? -ne 0 ]; then
    echo -e "${YELLOW}Creating EventBridge rule...${NC}"
    
    cat > event-pattern.json << EOF
{
    "source": ["aws.securityhub"],
    "detail-type": ["Security Hub Findings - Imported"]
}
EOF
    
    aws events put-rule \
        --name $RULE_NAME \
        --event-pattern file://event-pattern.json \
        --state ENABLED \
        --region $REGION
    
    # Add Lambda as target
    FUNCTION_ARN="arn:aws:lambda:$REGION:$ACCOUNT_ID:function:$FUNCTION_NAME"
    
    aws events put-targets \
        --rule $RULE_NAME \
        --targets "Id"="SIEMLambda","Arn"="$FUNCTION_ARN" \
        --region $REGION
    
    # Add permission for EventBridge to invoke Lambda
    aws lambda add-permission \
        --function-name $FUNCTION_NAME \
        --statement-id "EventBridgeSecurityHub" \
        --action "lambda:InvokeFunction" \
        --principal "events.amazonaws.com" \
        --source-arn "arn:aws:events:$REGION:$ACCOUNT_ID:rule/$RULE_NAME" \
        --region $REGION
    
    rm -f event-pattern.json
fi

# Test the function
echo -e "${YELLOW}Testing Lambda function...${NC}"

cat > test-event.json << EOF
{
    "source": "aws.securityhub",
    "detail-type": "Security Hub Findings - Imported",
    "detail": {
        "findings": [
            {
                "SchemaVersion": "2018-10-08",
                "Id": "test-finding-$(date +%s)",
                "ProductArn": "arn:aws:securityhub:$REGION::product/aws/securityhub",
                "GeneratorId": "test-generator",
                "AwsAccountId": "$ACCOUNT_ID",
                "Types": ["Software and Configuration Checks"],
                "CreatedAt": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
                "UpdatedAt": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
                "Severity": {"Label": "HIGH"},
                "Title": "Test Security Finding - Unauthorized API Call",
                "Description": "This is a test finding for the SIEM system",
                "Resources": [
                    {
                        "Type": "AwsEc2Instance",
                        "Id": "i-1234567890abcdef0"
                    }
                ],
                "ProductFields": {
                    "aws/securityhub/CompanyName": "AWS",
                    "aws/securityhub/FindingId": "arn:aws:securityhub:$REGION:$ACCOUNT_ID:subscription/aws-foundational-security-best-practices/v/1.0.0/Iam.1/finding/12345678-1234-1234-1234-123456789012"
                }
            }
        ]
    }
}
EOF

aws lambda invoke \
    --function-name $FUNCTION_NAME \
    --payload file://test-event.json \
    --region $REGION \
    test-response.json

echo -e "${GREEN}✅ Lambda function deployed successfully!${NC}"
echo -e "${YELLOW}Test response:${NC}"
cat test-response.json | python3 -m json.tool

# Clean up
rm -rf package test-event.json test-response.json

echo -e "${GREEN}🎉 Deployment complete!${NC}"
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Enable AWS Security Hub: aws securityhub enable-security-hub --region $REGION"
echo "2. Enable GuardDuty: aws guardduty create-detector --enable --region $REGION"
echo "3. Start Elasticsearch & Kibana: docker-compose up -d"
echo "4. Access Kibana at: http://localhost:5601"