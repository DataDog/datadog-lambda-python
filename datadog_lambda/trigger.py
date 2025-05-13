# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.

import gzip
import ujson as json
from io import BytesIO, BufferedReader
from enum import Enum
from typing import Any


class _stringTypedEnum(Enum):
    """
    _stringTypedEnum provides a type-hinted convenience function for getting the string value of
    an enum.
    """

    def get_string(self) -> str:
        return self.value


class EventTypes(_stringTypedEnum):
    """
    EventTypes is an enum of Lambda event types we care about.
    """

    UNKNOWN = "unknown"
    API_GATEWAY = "api-gateway"
    APPSYNC = "appsync"
    ALB = "application-load-balancer"
    CLOUDWATCH_LOGS = "cloudwatch-logs"
    CLOUDWATCH_EVENTS = "cloudwatch-events"
    CLOUDFRONT = "cloudfront"
    DYNAMODB = "dynamodb"
    EVENTBRIDGE = "eventbridge"
    KINESIS = "kinesis"
    LAMBDA_FUNCTION_URL = "lambda-function-url"
    S3 = "s3"
    SNS = "sns"
    SQS = "sqs"
    STEPFUNCTIONS = "states"


class EventSubtypes(_stringTypedEnum):
    """
    EventSubtypes is an enum of Lambda event subtypes.
    Currently, API Gateway events subtypes are supported,
    e.g. HTTP-API and Websocket events vs vanilla API-Gateway events.
    """

    NONE = "none"
    API_GATEWAY = "api-gateway"  # regular API Gateway
    WEBSOCKET = "websocket"
    HTTP_API = "http-api"


class _EventSource:
    """
    _EventSource holds an event's type and subtype.
    """

    def __init__(
        self,
        event_type: EventTypes,
        subtype: EventSubtypes = EventSubtypes.NONE,
    ):
        self.event_type = event_type
        self.subtype = subtype

    def to_string(self) -> str:
        """
        to_string returns the string representation of an _EventSource.
        Since to_string was added to support trigger tagging,
        the event's subtype will never be included in the string.
        """
        return self.event_type.get_string()

    def equals(
        self, event_type: EventTypes, subtype: EventSubtypes = EventSubtypes.NONE
    ) -> bool:
        """
        equals provides syntactic sugar to determine whether this _EventSource has a given type
        and subtype.
        Unknown events will never equal other events.
        """
        if self.event_type == EventTypes.UNKNOWN:
            return False
        if self.event_type != event_type:
            return False
        if self.subtype != subtype:
            return False
        return True


def get_aws_partition_by_region(region):
    if region.startswith("us-gov-"):
        return "aws-us-gov"
    if region.startswith("cn-"):
        return "aws-cn"
    return "aws"


def get_first_record(event):
    records = event.get("Records")
    if records and len(records) > 0:
        return records[0]


def parse_event_source(event: dict) -> _EventSource:
    """Determines the source of the trigger event"""
    if not isinstance(event, dict):
        return _EventSource(EventTypes.UNKNOWN)

    event_source = None

    # Get requestContext safely and ensure it's a dictionary
    request_context = event.get("requestContext")
    if not isinstance(request_context, dict):
        request_context = None

    if request_context and request_context.get("stage"):
        if "domainName" in request_context and detect_lambda_function_url_domain(
            request_context.get("domainName", "")
        ):
            return _EventSource(EventTypes.LAMBDA_FUNCTION_URL)
        event_source = _EventSource(EventTypes.API_GATEWAY)
        if "httpMethod" in event:
            event_source.subtype = EventSubtypes.API_GATEWAY
        if "routeKey" in event:
            event_source.subtype = EventSubtypes.HTTP_API
        if request_context.get("messageDirection"):
            event_source.subtype = EventSubtypes.WEBSOCKET

    if request_context and request_context.get("elb"):
        event_source = _EventSource(EventTypes.ALB)

    if event.get("awslogs"):
        event_source = _EventSource(EventTypes.CLOUDWATCH_LOGS)

    if event.get("detail-type"):
        event_source = _EventSource(EventTypes.EVENTBRIDGE)

    event_detail = event.get("detail")
    has_event_categories = (
        isinstance(event_detail, dict)
        and event_detail.get("EventCategories") is not None
    )
    if event.get("source") == "aws.events" or has_event_categories:
        event_source = _EventSource(EventTypes.CLOUDWATCH_EVENTS)

    if is_step_function_event(event):
        event_source = _EventSource(EventTypes.STEPFUNCTIONS)

    event_record = get_first_record(event)
    if event_record:
        aws_event_source = event_record.get("eventSource") or event_record.get(
            "EventSource"
        )
        if aws_event_source == "aws:dynamodb":
            event_source = _EventSource(EventTypes.DYNAMODB)
        if aws_event_source == "aws:kinesis":
            event_source = _EventSource(EventTypes.KINESIS)
        if aws_event_source == "aws:s3":
            event_source = _EventSource(EventTypes.S3)
        if aws_event_source == "aws:sns":
            event_source = _EventSource(EventTypes.SNS)
        if aws_event_source == "aws:sqs":
            event_source = _EventSource(EventTypes.SQS)
        if event_record.get("cf"):
            event_source = _EventSource(EventTypes.CLOUDFRONT)

    return event_source or _EventSource(EventTypes.UNKNOWN)


def detect_lambda_function_url_domain(domain: str) -> bool:
    #  e.g. "etsn5fibjr.lambda-url.eu-south-1.amazonaws.com"
    if not isinstance(domain, str):
        return False
    domain_parts = domain.split(".")
    if len(domain_parts) < 2:
        return False
    return domain_parts[1] == "lambda-url"


def parse_event_source_arn(source: _EventSource, event: dict, context: Any) -> str:
    """
    Parses the trigger event for an available ARN. If an ARN field is not provided
    in the event we stitch it together.
    """
    split_function_arn = context.invoked_function_arn.split(":")
    region = split_function_arn[3]
    account_id = split_function_arn[4]
    aws_arn = get_aws_partition_by_region(region)

    event_record = get_first_record(event)
    # e.g. arn:aws:s3:::lambda-xyz123-abc890
    if source.to_string() == "s3":
        s3 = event_record.get("s3")
        if s3:
            bucket = s3.get("bucket")
            if bucket:
                return bucket.get("arn")
        return None

    # e.g. arn:aws:sns:us-east-1:123456789012:sns-lambda
    if source.to_string() == "sns":
        sns = event_record.get("Sns")
        if sns:
            return sns.get("TopicArn")
        return None

    # e.g. arn:aws:cloudfront::123456789012:distribution/ABC123XYZ
    if source.event_type == EventTypes.CLOUDFRONT:
        distribution_id = (
            event_record.get("cf", {}).get("config", {}).get("distributionId")
        )
        return f"arn:{aws_arn}:cloudfront::{account_id}:distribution/{distribution_id}"

    # e.g. arn:aws:lambda:<region>:<account_id>:url:<function-name>:<function-qualifier>
    if source.equals(EventTypes.LAMBDA_FUNCTION_URL):
        function_name = ""
        if len(split_function_arn) >= 7:
            function_name = split_function_arn[6]
        function_arn = f"arn:aws:lambda:{region}:{account_id}:url:{function_name}"
        function_qualifier = ""
        if len(split_function_arn) >= 8:
            function_qualifier = split_function_arn[7]
            function_arn = function_arn + f":{function_qualifier}"
        return function_arn

    # e.g. arn:aws:apigateway:us-east-1::/restapis/xyz123/stages/default
    if source.event_type == EventTypes.API_GATEWAY:
        request_context = event.get("requestContext")
        api_id = request_context.get("apiId")
        stage = request_context.get("stage")
        return f"arn:{aws_arn}:apigateway:{region}::/restapis/{api_id}/stages/{stage}"

    # e.g. arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/lambda-xyz/123
    if source.event_type == EventTypes.ALB:
        request_context = event.get("requestContext")
        if request_context:
            elb = request_context.get("elb")
            if elb:
                return elb.get("targetGroupArn")
        return None

    # e.g. arn:aws:logs:us-west-1:123456789012:log-group:/my-log-group-xyz
    if source.event_type == EventTypes.CLOUDWATCH_LOGS:
        import base64

        with gzip.GzipFile(
            fileobj=BytesIO(base64.b64decode(event.get("awslogs", {}).get("data")))
        ) as decompress_stream:
            data = b"".join(BufferedReader(decompress_stream))
        logs = json.loads(data)
        log_group = logs.get("logGroup", "cloudwatch")
        return f"arn:{aws_arn}:logs:{region}:{account_id}:log-group:{log_group}"

    # e.g. arn:aws:events:us-east-1:123456789012:rule/my-schedule
    if source.event_type == EventTypes.CLOUDWATCH_EVENTS and event.get("resources"):
        return event.get("resources")[0]

    # Returning state machine arn as event source arn.
    if source.event_type == EventTypes.STEPFUNCTIONS:
        context = event
        if "_datadog" in event:
            context = event.get("_datadog")
        return context.get("StateMachine").get("Id")


def get_event_source_arn(source: _EventSource, event: dict, context: Any) -> str:
    event_source_arn = event.get("eventSourceARN") or event.get("eventSourceArn")

    event_record = get_first_record(event)
    if event_record:
        event_source_arn = event_record.get("eventSourceARN") or event_record.get(
            "eventSourceArn"
        )

    if event_source_arn is None:
        event_source_arn = parse_event_source_arn(source, event, context)

    return event_source_arn


def extract_http_tags(event):
    """
    Extracts HTTP facet tags from the triggering event
    """
    http_tags = {}

    # Safely get request_context and ensure it's a dictionary
    request_context = event.get("requestContext") or {}
    if not isinstance(request_context, dict):
        request_context = None

    path = event.get("path")
    method = event.get("httpMethod")

    if request_context and request_context.get("stage"):
        domain_name = request_context.get("domainName")
        if domain_name:
            http_tags["http.url"] = domain_name

        path = request_context.get("path")
        method = request_context.get("httpMethod")

        # Version 2.0 HTTP API Gateway
        apigateway_v2_http = request_context.get("http", {})
        if not isinstance(apigateway_v2_http, dict):
            apigateway_v2_http = {}

        if event.get("version") == "2.0" and apigateway_v2_http:
            path = apigateway_v2_http.get("path")
            method = apigateway_v2_http.get("method")

    if path:
        http_tags["http.url_details.path"] = path
    if method:
        http_tags["http.method"] = method

    # Safely get headers
    headers = event.get("headers", {})
    if not isinstance(headers, dict):
        headers = {}

    if headers and headers.get("Referer"):
        http_tags["http.referer"] = headers.get("Referer")

    # Try to get `routeKey` from API GW v2; otherwise try to get `resource` from API GW v1
    route = event.get("routeKey") or event.get("resource")
    if route and isinstance(route, str):
        try:
            # "GET /my/endpoint" = > "/my/endpoint"
            http_tags["http.route"] = route.split(" ")[-1]
        except Exception:
            # If splitting fails, use the route as is
            http_tags["http.route"] = route

    return http_tags


_http_event_types = (
    EventTypes.API_GATEWAY,
    EventTypes.ALB,
    EventTypes.LAMBDA_FUNCTION_URL,
)


def extract_trigger_tags(event: dict, context: Any) -> dict:
    """
    Parses the trigger event object to get tags to be added to the span metadata
    """
    trigger_tags = {}
    event_source = parse_event_source(event)
    if event_source.to_string() is not None and event_source.to_string() != "unknown":
        trigger_tags["function_trigger.event_source"] = event_source.to_string()

        event_source_arn = get_event_source_arn(event_source, event, context)
        if event_source_arn:
            trigger_tags["function_trigger.event_source_arn"] = event_source_arn

    if event_source.event_type in _http_event_types:
        trigger_tags.update(extract_http_tags(event))

    return trigger_tags


_str_http_triggers = [et.value for et in _http_event_types]


def extract_http_status_code_tag(trigger_tags, response):
    """
    If the Lambda was triggered by API Gateway, Lambda Function URL, or ALB,
    add the returned status code as a tag to the function execution span.
    """
    if trigger_tags is None:
        return
    str_event_source = trigger_tags.get("function_trigger.event_source")
    # it would be cleaner if each event type was a constant object that
    # knew some properties about itself like this.
    if str_event_source not in _str_http_triggers:
        return

    status_code = "200"
    if response is None:
        # Return a 502 status if no response is found
        status_code = "502"
    elif hasattr(response, "get"):
        status_code = response.get("statusCode")
    elif hasattr(response, "status_code"):
        status_code = response.status_code

    return str(status_code)


def is_step_function_event(event):
    """
    Check if the event is a step function that invoked the current lambda.

    The whole event can be wrapped in "Payload" in Legacy Lambda cases. There may also be a
    "_datadog" for JSONata style context propagation.

    The actual event must contain "Execution", "StateMachine", and "State" fields.
    """
    event = event.get("Payload", event)

    # JSONPath style
    if "Execution" in event and "StateMachine" in event and "State" in event:
        return True

    # JSONata style
    dd_context = event.get("_datadog")
    return (
        dd_context
        and "Execution" in dd_context
        and "StateMachine" in dd_context
        and "State" in dd_context
        and "serverless-version" in dd_context
    )
