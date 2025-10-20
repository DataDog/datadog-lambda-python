layer_arn=$(
aws-vault exec sso-serverless-sandbox-account-admin -- \
	aws lambda publish-layer-version --layer-name "Python312-discard-all-rithika" \
		--description "Datadog Tracer Lambda Layer for Python" \
		--zip-file "fileb://./discard-all.zip" \
		--region "us-west-2" \
		--output json \
			| jq -r '.LayerVersionArn')

echo $layer_arn
