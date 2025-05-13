import unittest
import json

from unittest.mock import MagicMock

from datadog_lambda.trigger import (
    EventSubtypes,
    parse_event_source,
    get_event_source_arn,
    extract_trigger_tags,
    extract_http_status_code_tag,
    is_step_function_event,
)

from tests.utils import get_mock_context

event_samples = "tests/event_samples/"
function_arn = "arn:aws:lambda:us-west-1:123457598159:function:python-layer-test"


class TestGetEventSourceAndARN(unittest.TestCase):
    def test_event_source_api_gateway(self):
        event_sample_source = "api-gateway"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        event_source = parse_event_source(event)
        event_source_arn = get_event_source_arn(event_source, event, ctx)
        self.assertEqual(event_source.to_string(), event_sample_source)
        self.assertEqual(
            event_source_arn,
            "arn:aws:apigateway:us-west-1::/restapis/1234567890/stages/prod",
        )

    def test_event_source_api_gateway_non_proxy(self):
        event_sample_source = "api-gateway-non-proxy"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        event_source = parse_event_source(event)
        event_source_arn = get_event_source_arn(event_source, event, ctx)
        self.assertEqual(event_source.to_string(), "api-gateway")
        self.assertEqual(event_source.subtype, EventSubtypes.API_GATEWAY)
        self.assertEqual(
            event_source_arn,
            "arn:aws:apigateway:us-west-1::/restapis/lgxbo6a518/stages/dev",
        )

    def test_event_source_api_gateway_websocket_connect(self):
        event_sample_source = "api-gateway-websocket-connect"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        event_source = parse_event_source(event)
        event_source_arn = get_event_source_arn(event_source, event, ctx)
        self.assertEqual(event_source.to_string(), "api-gateway")
        self.assertEqual(event_source.subtype, EventSubtypes.WEBSOCKET)
        self.assertEqual(
            event_source_arn,
            "arn:aws:apigateway:us-west-1::/restapis/p62c47itsb/stages/dev",
        )

    def test_event_source_api_gateway_websocket_default(self):
        event_sample_source = "api-gateway-websocket-default"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        event_source = parse_event_source(event)
        event_source_arn = get_event_source_arn(event_source, event, ctx)
        self.assertEqual(event_source.to_string(), "api-gateway")
        self.assertEqual(event_source.subtype, EventSubtypes.WEBSOCKET)
        self.assertEqual(
            event_source_arn,
            "arn:aws:apigateway:us-west-1::/restapis/p62c47itsb/stages/dev",
        )

    def test_event_source_api_gateway_websocket_disconnect(self):
        event_sample_source = "api-gateway-websocket-disconnect"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        event_source = parse_event_source(event)
        event_source_arn = get_event_source_arn(event_source, event, ctx)
        self.assertEqual(event_source.to_string(), "api-gateway")
        self.assertEqual(event_source.subtype, EventSubtypes.WEBSOCKET)
        self.assertEqual(
            event_source_arn,
            "arn:aws:apigateway:us-west-1::/restapis/p62c47itsb/stages/dev",
        )

    def test_event_source_api_gateway_http_api(self):
        event_sample_source = "http-api"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        event_source = parse_event_source(event)
        event_source_arn = get_event_source_arn(event_source, event, ctx)
        self.assertEqual(event_source.to_string(), "api-gateway")
        self.assertEqual(event_source.subtype, EventSubtypes.HTTP_API)
        self.assertEqual(
            event_source_arn,
            "arn:aws:apigateway:us-west-1::/restapis/x02yirxc7a/stages/$default",
        )

    def test_event_source_application_load_balancer(self):
        event_sample_source = "application-load-balancer"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        event_source = parse_event_source(event)
        event_source_arn = get_event_source_arn(event_source, event, ctx)
        self.assertEqual(event_source.to_string(), event_sample_source)
        self.assertEqual(
            event_source_arn,
            "arn:aws:elasticloadbalancing:us-east-2:123456789012:targetgroup/lambda-xyz/123abc",
        )

    def test_event_source_cloudfront(self):
        event_sample_source = "cloudfront"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        event_source = parse_event_source(event)
        event_source_arn = get_event_source_arn(event_source, event, ctx)
        self.assertEqual(event_source.to_string(), event_sample_source)
        self.assertEqual(
            event_source_arn, "arn:aws:cloudfront::123457598159:distribution/EXAMPLE"
        )

    def test_event_source_cloudwatch_events(self):
        event_sample_source = "cloudwatch-events"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        event_source = parse_event_source(event)
        event_source_arn = get_event_source_arn(event_source, event, ctx)
        self.assertEqual(event_source.to_string(), event_sample_source)
        self.assertEqual(
            event_source_arn, "arn:aws:events:us-east-1:123456789012:rule/ExampleRule"
        )

    def test_event_source_cloudwatch_logs(self):
        event_sample_source = "cloudwatch-logs"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        event_source = parse_event_source(event)
        event_source_arn = get_event_source_arn(event_source, event, ctx)
        self.assertEqual(event_source.to_string(), event_sample_source)
        self.assertEqual(
            event_source_arn,
            "arn:aws:logs:us-west-1:123457598159:log-group:testLogGroup",
        )

    def test_event_source_dynamodb(self):
        event_sample_source = "dynamodb"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        event_source = parse_event_source(event)
        event_source_arn = get_event_source_arn(event_source, event, ctx)
        self.assertEqual(event_source.to_string(), event_sample_source)
        self.assertEqual(
            event_source_arn,
            "arn:aws:dynamodb:us-east-1:123456789012:table/ExampleTableWithStream/stream/2015-06-27T00:48:05.899",
        )

    def test_event_source_kinesis(self):
        event_sample_source = "kinesis"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        event_source = parse_event_source(event)
        event_source_arn = get_event_source_arn(event_source, event, ctx)
        self.assertEqual(event_source.to_string(), event_sample_source)
        self.assertEqual(
            event_source_arn,
            "arn:aws:kinesis:eu-west-1:601427279990:stream/kinesisStream",
        )

    def test_event_source_s3(self):
        event_sample_source = "s3"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        event_source = parse_event_source(event)
        event_source_arn = get_event_source_arn(event_source, event, ctx)
        self.assertEqual(event_source.to_string(), event_sample_source)
        self.assertEqual(event_source_arn, "arn:aws:s3:::example-bucket")

    def test_event_source_sns(self):
        event_sample_source = "sns"
        event_sample_name = "sns-string-msg-attribute"
        test_file = event_samples + event_sample_name + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        event_source = parse_event_source(event)
        event_source_arn = get_event_source_arn(event_source, event, ctx)
        self.assertEqual(event_source.to_string(), event_sample_source)
        self.assertEqual(
            event_source_arn,
            "arn:aws:sns:eu-west-1:601427279990:serverlessTracingTopicPy",
        )

    def test_event_source_sqs(self):
        event_sample_source = "sqs"
        event_sample_name = "sqs-string-msg-attribute"
        test_file = event_samples + event_sample_name + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        event_source = parse_event_source(event)
        event_source_arn = get_event_source_arn(event_source, event, ctx)
        self.assertEqual(event_source.to_string(), event_sample_source)
        self.assertEqual(
            event_source_arn,
            "arn:aws:sqs:eu-west-1:601427279990:InferredSpansQueueNode",
        )

    def test_event_source_stepfunctions(self):
        event_sample_source = "states"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        event_source = parse_event_source(event)
        event_source_arn = get_event_source_arn(event_source, event, ctx)
        self.assertEqual(event_source.to_string(), event_sample_source)
        self.assertEqual(
            event_source_arn,
            "arn:aws:states:ca-central-1:425362996713:stateMachine:MyStateMachine-wsx8chv4d",
        )

    def test_event_source_unsupported(self):
        event_sample_source = "custom"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        event_source = parse_event_source(event)
        event_source_arn = get_event_source_arn(event_source, event, ctx)
        self.assertEqual(event_source.to_string(), "unknown")
        self.assertEqual(event_source_arn, None)

    def test_event_source_with_non_dict_request_context(self):
        # Test with requestContext as a string instead of a dict
        event = {"requestContext": "not_a_dict"}
        event_source = parse_event_source(event)
        # Should still return a valid event source (unknown in this case)
        self.assertEqual(event_source.to_string(), "unknown")

    def test_event_source_with_invalid_domain_name(self):
        # Test with domainName that isn't a string
        event = {"requestContext": {"stage": "prod", "domainName": 12345}}
        event_source = parse_event_source(event)
        # Should detect as API Gateway since stage is present
        self.assertEqual(event_source.to_string(), "api-gateway")

    def test_detect_lambda_function_url_domain_with_invalid_input(self):
        from datadog_lambda.trigger import detect_lambda_function_url_domain

        # Test with non-string input
        self.assertFalse(detect_lambda_function_url_domain(None))
        self.assertFalse(detect_lambda_function_url_domain(12345))
        self.assertFalse(detect_lambda_function_url_domain({"not": "a-string"}))
        # Test with string that would normally cause an exception when split
        self.assertFalse(detect_lambda_function_url_domain(""))


class GetTriggerTags(unittest.TestCase):
    def test_extract_trigger_tags_api_gateway(self):
        event_sample_source = "api-gateway"
        test_file = event_samples + event_sample_source + ".json"
        ctx = get_mock_context()
        with open(test_file, "r") as event:
            event = json.load(event)
        tags = extract_trigger_tags(event, ctx)
        self.assertEqual(
            tags,
            {
                "function_trigger.event_source": "api-gateway",
                "function_trigger.event_source_arn": "arn:aws:apigateway:us-west-1::/restapis/1234567890/stages/prod",
                "http.url": "70ixmpl4fl.execute-api.us-east-2.amazonaws.com",
                "http.url_details.path": "/prod/path/to/resource",
                "http.method": "POST",
                "http.route": "/{proxy+}",
            },
        )

    def test_extract_trigger_tags_api_gateway_non_proxy(self):
        event_sample_source = "api-gateway-non-proxy"
        test_file = event_samples + event_sample_source + ".json"
        ctx = get_mock_context()
        with open(test_file, "r") as event:
            event = json.load(event)
        tags = extract_trigger_tags(event, ctx)
        self.assertEqual(
            tags,
            {
                "function_trigger.event_source": "api-gateway",
                "function_trigger.event_source_arn": "arn:aws:apigateway:us-west-1::/restapis/lgxbo6a518/stages/dev",
                "http.url": "lgxbo6a518.execute-api.eu-west-1.amazonaws.com",
                "http.url_details.path": "/dev/http/get",
                "http.method": "GET",
                "http.route": "/http/get",
            },
        )

    def test_extract_trigger_tags_api_gateway_websocket_connect(self):
        event_sample_source = "api-gateway-websocket-connect"
        test_file = event_samples + event_sample_source + ".json"
        ctx = get_mock_context()
        with open(test_file, "r") as event:
            event = json.load(event)
        tags = extract_trigger_tags(event, ctx)
        self.assertEqual(
            tags,
            {
                "function_trigger.event_source": "api-gateway",
                "function_trigger.event_source_arn": "arn:aws:apigateway:us-west-1::/restapis/p62c47itsb/stages/dev",
                "http.url": "p62c47itsb.execute-api.eu-west-1.amazonaws.com",
            },
        )

    def test_extract_trigger_tags_api_gateway_websocket_default(self):
        event_sample_source = "api-gateway-websocket-default"
        test_file = event_samples + event_sample_source + ".json"
        ctx = get_mock_context()
        with open(test_file, "r") as event:
            event = json.load(event)
        tags = extract_trigger_tags(event, ctx)
        self.assertEqual(
            tags,
            {
                "function_trigger.event_source": "api-gateway",
                "function_trigger.event_source_arn": "arn:aws:apigateway:us-west-1::/restapis/p62c47itsb/stages/dev",
                "http.url": "p62c47itsb.execute-api.eu-west-1.amazonaws.com",
            },
        )

    def test_extract_trigger_tags_api_gateway_websocket_disconnect(self):
        event_sample_source = "api-gateway-websocket-disconnect"
        test_file = event_samples + event_sample_source + ".json"
        ctx = get_mock_context()
        with open(test_file, "r") as event:
            event = json.load(event)
        tags = extract_trigger_tags(event, ctx)
        self.assertEqual(
            tags,
            {
                "function_trigger.event_source": "api-gateway",
                "function_trigger.event_source_arn": "arn:aws:apigateway:us-west-1::/restapis/p62c47itsb/stages/dev",
                "http.url": "p62c47itsb.execute-api.eu-west-1.amazonaws.com",
            },
        )

    def test_extract_trigger_tags_api_gateway_http_api(self):
        event_sample_source = "http-api"
        test_file = event_samples + event_sample_source + ".json"
        ctx = get_mock_context()
        with open(test_file, "r") as event:
            event = json.load(event)
        tags = extract_trigger_tags(event, ctx)
        self.assertEqual(
            tags,
            {
                "function_trigger.event_source": "api-gateway",
                "function_trigger.event_source_arn": "arn:aws:apigateway:us-west-1::/restapis/x02yirxc7a/stages/$default",
                "http.url": "x02yirxc7a.execute-api.eu-west-1.amazonaws.com",
                "http.url_details.path": "/httpapi/get",
                "http.method": "GET",
                "http.route": "/httpapi/get",
            },
        )

    def test_extract_trigger_tags_application_load_balancer(self):
        event_sample_source = "application-load-balancer"
        test_file = event_samples + event_sample_source + ".json"
        ctx = get_mock_context()
        with open(test_file, "r") as event:
            event = json.load(event)
        tags = extract_trigger_tags(event, ctx)
        self.assertEqual(
            tags,
            {
                "function_trigger.event_source": "application-load-balancer",
                "function_trigger.event_source_arn": "arn:aws:elasticloadbalancing:us-east-2:123456789012:targetgroup/lambda-xyz/123abc",
                "http.url_details.path": "/lambda",
                "http.method": "GET",
            },
        )

    def test_extract_trigger_tags_cloudfront(self):
        event_sample_source = "cloudfront"
        test_file = event_samples + event_sample_source + ".json"
        ctx = get_mock_context()
        with open(test_file, "r") as event:
            event = json.load(event)
        tags = extract_trigger_tags(event, ctx)
        self.assertEqual(
            tags,
            {
                "function_trigger.event_source": "cloudfront",
                "function_trigger.event_source_arn": "arn:aws:cloudfront::123457598159:distribution/EXAMPLE",
            },
        )

    def test_extract_trigger_tags_cloudwatch_events(self):
        event_sample_source = "cloudwatch-events"
        test_file = event_samples + event_sample_source + ".json"
        ctx = get_mock_context()
        with open(test_file, "r") as event:
            event = json.load(event)
        tags = extract_trigger_tags(event, ctx)
        self.assertEqual(
            tags,
            {
                "function_trigger.event_source": "cloudwatch-events",
                "function_trigger.event_source_arn": "arn:aws:events:us-east-1:123456789012:rule/ExampleRule",
            },
        )

    def test_extract_trigger_tags_cloudwatch_logs(self):
        event_sample_source = "cloudwatch-logs"
        test_file = event_samples + event_sample_source + ".json"
        ctx = get_mock_context()
        with open(test_file, "r") as event:
            event = json.load(event)
        tags = extract_trigger_tags(event, ctx)
        self.assertEqual(
            tags,
            {
                "function_trigger.event_source": "cloudwatch-logs",
                "function_trigger.event_source_arn": "arn:aws:logs:us-west-1:123457598159:log-group:testLogGroup",
            },
        )

    def test_extract_trigger_tags_dynamodb(self):
        event_sample_source = "dynamodb"
        test_file = event_samples + event_sample_source + ".json"
        ctx = get_mock_context()
        with open(test_file, "r") as event:
            event = json.load(event)
        tags = extract_trigger_tags(event, ctx)
        self.assertEqual(
            tags,
            {
                "function_trigger.event_source": "dynamodb",
                "function_trigger.event_source_arn": "arn:aws:dynamodb:us-east-1:123456789012:table/ExampleTableWithStream/stream/2015-06-27T00:48:05.899",
            },
        )

    def test_extract_trigger_tags_kinesis(self):
        event_sample_source = "kinesis"
        test_file = event_samples + event_sample_source + ".json"
        ctx = get_mock_context()
        with open(test_file, "r") as event:
            event = json.load(event)
        tags = extract_trigger_tags(event, ctx)
        self.assertEqual(
            tags,
            {
                "function_trigger.event_source": "kinesis",
                "function_trigger.event_source_arn": "arn:aws:kinesis:eu-west-1:601427279990:stream/kinesisStream",
            },
        )

    def test_extract_trigger_tags_s3(self):
        event_sample_source = "s3"
        test_file = event_samples + event_sample_source + ".json"
        ctx = get_mock_context()
        with open(test_file, "r") as event:
            event = json.load(event)
        tags = extract_trigger_tags(event, ctx)
        self.assertEqual(
            tags,
            {
                "function_trigger.event_source": "s3",
                "function_trigger.event_source_arn": "arn:aws:s3:::example-bucket",
            },
        )

    def test_extract_trigger_tags_sns(self):
        event_sample_name = "sns-string-msg-attribute"
        test_file = event_samples + event_sample_name + ".json"
        ctx = get_mock_context()
        with open(test_file, "r") as event:
            event = json.load(event)
        tags = extract_trigger_tags(event, ctx)
        self.assertEqual(
            tags,
            {
                "function_trigger.event_source": "sns",
                "function_trigger.event_source_arn": "arn:aws:sns:eu-west-1:601427279990:serverlessTracingTopicPy",
            },
        )

    def test_extract_trigger_tags_sqs(self):
        event_sample_name = "sqs-string-msg-attribute"
        test_file = event_samples + event_sample_name + ".json"
        ctx = get_mock_context()
        with open(test_file, "r") as event:
            event = json.load(event)
        tags = extract_trigger_tags(event, ctx)
        self.assertEqual(
            tags,
            {
                "function_trigger.event_source": "sqs",
                "function_trigger.event_source_arn": "arn:aws:sqs:eu-west-1:601427279990:InferredSpansQueueNode",
            },
        )

    def test_extract_trigger_tags_stepfunctions(self):
        event_sample_source = "states"
        test_file = event_samples + event_sample_source + ".json"
        ctx = get_mock_context()
        with open(test_file, "r") as event:
            event = json.load(event)
        tags = extract_trigger_tags(event, ctx)
        self.assertEqual(
            tags,
            {
                "function_trigger.event_source": "states",
                "function_trigger.event_source_arn": "arn:aws:states:ca-central-1:425362996713:stateMachine:MyStateMachine-wsx8chv4d",
            },
        )

    def test_extract_trigger_tags_unsupported(self):
        event_sample_source = "custom"
        test_file = event_samples + event_sample_source + ".json"
        ctx = get_mock_context()
        with open(test_file, "r") as event:
            event = json.load(event)
        tags = extract_trigger_tags(event, ctx)
        self.assertEqual(tags, {})

    def test_extract_trigger_tags_list_type_event(self):
        event = []
        ctx = get_mock_context()
        tags = extract_trigger_tags(event, ctx)
        self.assertEqual(tags, {})

    def test_extract_http_tags_with_invalid_request_context(self):
        from datadog_lambda.trigger import extract_http_tags

        # Test with requestContext as a string instead of a dict
        event = {"requestContext": "not_a_dict", "path": "/test", "httpMethod": "GET"}
        http_tags = extract_http_tags(event)
        # Should still extract valid tags from the event
        self.assertEqual(
            http_tags, {"http.url_details.path": "/test", "http.method": "GET"}
        )

    def test_extract_http_tags_with_invalid_apigateway_http(self):
        from datadog_lambda.trigger import extract_http_tags

        # Test with http in requestContext that's not a dict
        event = {
            "requestContext": {"stage": "prod", "http": "not_a_dict"},
            "version": "2.0",
        }
        http_tags = extract_http_tags(event)
        # Should not raise an exception
        self.assertEqual(http_tags, {})

    def test_extract_http_tags_with_invalid_headers(self):
        from datadog_lambda.trigger import extract_http_tags

        # Test with headers that's not a dict
        event = {"headers": "not_a_dict"}
        http_tags = extract_http_tags(event)
        # Should not raise an exception
        self.assertEqual(http_tags, {})

    def test_extract_http_tags_with_invalid_route(self):
        from datadog_lambda.trigger import extract_http_tags

        # Test with routeKey that would cause a split error
        event = {"routeKey": 12345}  # Not a string
        http_tags = extract_http_tags(event)
        # Should not raise an exception
        self.assertEqual(http_tags, {})


class ExtractHTTPStatusCodeTag(unittest.TestCase):
    def test_extract_http_status_code_tag_from_response_dict(self):
        trigger_tags = {"function_trigger.event_source": "api-gateway"}
        response = {"statusCode": 403}
        status_code = extract_http_status_code_tag(trigger_tags, response)
        self.assertEqual(status_code, "403")

    def test_extract_http_status_code_tag_from_response_object(self):
        trigger_tags = {"function_trigger.event_source": "api-gateway"}
        response = MagicMock(spec=["status_code"])
        response.status_code = 403
        status_code = extract_http_status_code_tag(trigger_tags, response)
        self.assertEqual(status_code, "403")


class IsStepFunctionEvent(unittest.TestCase):
    def test_is_step_function_event_jsonata(self):
        event = {
            "_datadog": {
                "Execution": {
                    "Id": "665c417c-1237-4742-aaca-8b3becbb9e75",
                    "RedriveCount": 0,
                },
                "StateMachine": {},
                "State": {
                    "Name": "my-awesome-state",
                    "EnteredTime": "Mon Nov 13 12:43:33 PST 2023",
                    "RetryCount": 0,
                },
                "x-datadog-trace-id": "5821803790426892636",
                "x-datadog-tags": "_dd.p.dm=-0,_dd.p.tid=672a7cb100000000",
                "serverless-version": "v1",
            }
        }
        self.assertTrue(is_step_function_event(event))

    def test_is_step_function_event_jsonpath(self):
        event = {
            "Execution": {
                "Id": "665c417c-1237-4742-aaca-8b3becbb9e75",
                "RedriveCount": 0,
            },
            "StateMachine": {},
            "State": {
                "Name": "my-awesome-state",
                "EnteredTime": "Mon Nov 13 12:43:33 PST 2023",
                "RetryCount": 0,
            },
        }
        self.assertTrue(is_step_function_event(event))

    def test_is_step_function_event_legacy_lambda(self):
        event = {
            "Payload": {
                "Execution": {
                    "Id": "665c417c-1237-4742-aaca-8b3becbb9e75",
                    "RedriveCount": 0,
                },
                "StateMachine": {},
                "State": {
                    "Name": "my-awesome-state",
                    "EnteredTime": "Mon Nov 13 12:43:33 PST 2023",
                    "RetryCount": 0,
                },
            }
        }
        self.assertTrue(is_step_function_event(event))

    def test_is_step_function_event_dd_header(self):
        event = {
            "_datadog": {
                "x-datadog-trace-id": "5821803790426892636",
                "x-datadog-parent-id": "5821803790426892636",
                "x-datadog-tags": "_dd.p.dm=-0,_dd.p.tid=672a7cb100000000",
                "x-datadog-sampling-priority": "1",
            }
        }
        self.assertFalse(is_step_function_event(event))
