REGION=us-east-1 PYTHON_VERSION=$PYTHON_VERSION ARCH=$ARCH ./scripts/build_layers.sh

LAYER_NAME="Python${PYTHON_VERSION/3./3}-RITHIKA"
LAYER_ZIP=".layers/datadog_lambda_py-${ARCH}-${PYTHON_VERSION}.zip"
REGION="us-east-1"

echo "zipping package files"
PYTHON_VERSION=$PYTHON_VERSION ARCH=$ARCH ./scripts/build_layers.sh

echo "publishing layer"

layer_arn=$(
    aws-vault exec sso-serverless-sandbox-account-admin -- \
        aws lambda publish-layer-version --layer-name $LAYER_NAME \
            --description "Datadog Tracer Lambda Layer for Python" \
            --zip-file "fileb://$LAYER_ZIP" \
            --region "$REGION" \
            --output json \
                | jq -r '.LayerVersionArn')

echo "new python layer published $layer_arn"