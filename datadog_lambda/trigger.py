# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.

import base64
import gzip
import json
from io import BytesIO, BufferedReader
from enum import Enum
from typing import Any, Optional


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
    KINESIS = "kinesis"
    S3 = "s3"
    SNS = "sns"
    SQS = "sqs"


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
        if event_type is None:
            self.event_type = EventTypes.UNKNOWN
        else:
            self.event_type = event_type
        self.subtype = subtype

    def to_string(self) -> Optional[str]:
        """
        to_string returns the string representation of an _EventSource.
        Since to_string was added to support trigger tagging,
        the event's subtype will never be included in the string.
        """
        if self.event_type == EventTypes.UNKNOWN:
            return None
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
    if type(event) is not dict:
        return _EventSource(EventTypes.UNKNOWN)

    event_source = _EventSource(EventTypes.UNKNOWN)

    request_context = event.get("requestContext")
    if request_context and request_context.get("stage"):
        event_source = _EventSource(EventTypes.API_GATEWAY)
        if "httpMethod" in event:
            event_source.subtype = EventSubtypes.API_GATEWAY
        if "routeKey" in event:
            event_source.subtype = EventSubtypes.HTTP_API
        if "requestContext" in event and "messageDirection" in event["requestContext"]:
            event_source.subtype = EventSubtypes.WEBSOCKET

    if request_context and request_context.get("elb"):
        event_source = _EventSource(EventTypes.ALB)

    if event.get("awslogs"):
        event_source = _EventSource(EventTypes.CLOUDWATCH_LOGS)

    event_detail = event.get("detail")
    cw_event_categories = event_detail and event_detail.get("EventCategories")
    if event.get("source") == "aws.events" or cw_event_categories:
        event_source = _EventSource(EventTypes.CLOUDWATCH_EVENTS)

    event_record = get_first_record(event)
    if event_record:
        aws_event_source = event_record.get(
            "eventSource", event_record.get("EventSource")
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

    return event_source


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
        return event_record.get("s3")["bucket"]["arn"]

    # e.g. arn:aws:sns:us-east-1:123456789012:sns-lambda
    if source.to_string() == "sns":
        return event_record.get("Sns")["TopicArn"]

    # e.g. arn:aws:cloudfront::123456789012:distribution/ABC123XYZ
    if source.event_type == EventTypes.CLOUDFRONT:
        distribution_id = event_record.get("cf")["config"]["distributionId"]
        return "arn:{}:cloudfront::{}:distribution/{}".format(
            aws_arn, account_id, distribution_id
        )

    # e.g. arn:aws:apigateway:us-east-1::/restapis/xyz123/stages/default
    if source.event_type == EventTypes.API_GATEWAY:
        request_context = event.get("requestContext")
        return "arn:{}:apigateway:{}::/restapis/{}/stages/{}".format(
            aws_arn, region, request_context["apiId"], request_context["stage"]
        )

    # e.g. arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/lambda-xyz/123
    if source.event_type == EventTypes.ALB:
        request_context = event.get("requestContext")
        return request_context.get("elb")["targetGroupArn"]

    # e.g. arn:aws:logs:us-west-1:123456789012:log-group:/my-log-group-xyz
    if source.event_type == EventTypes.CLOUDWATCH_LOGS:
        with gzip.GzipFile(
            fileobj=BytesIO(base64.b64decode(event["awslogs"]["data"]))
        ) as decompress_stream:
            data = b"".join(BufferedReader(decompress_stream))
        logs = json.loads(data)
        log_group = logs.get("logGroup", "cloudwatch")
        return "arn:{}:logs:{}:{}:log-group:{}".format(
            aws_arn, region, account_id, log_group
        )

    # e.g. arn:aws:events:us-east-1:123456789012:rule/my-schedule
    if source.event_type == EventTypes.CLOUDWATCH_EVENTS and event.get("resources"):
        return event.get("resources")[0]


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
    request_context = event.get("requestContext")
    path = event.get("path")
    method = event.get("httpMethod")
    if request_context and request_context.get("stage"):
        if request_context.get("domainName"):
            http_tags["http.url"] = request_context["domainName"]

        path = request_context.get("path")
        method = request_context.get("httpMethod")
        # Version 2.0 HTTP API Gateway
        apigateway_v2_http = request_context.get("http")
        if event.get("version") == "2.0" and apigateway_v2_http:
            path = apigateway_v2_http.get("path")
            method = apigateway_v2_http.get("method")

    if path:
        http_tags["http.url_details.path"] = path
    if method:
        http_tags["http.method"] = method

    headers = event.get("headers")
    if headers and headers.get("Referer"):
        http_tags["http.referer"] = headers["Referer"]

    return http_tags


def extract_trigger_tags(event: dict, context: Any) -> dict:
    """
    Parses the trigger event object to get tags to be added to the span metadata
    """
    trigger_tags = {}
    event_source = parse_event_source(event)
    if event_source.event_type != EventTypes.UNKNOWN:
        trigger_tags["function_trigger.event_source"] = event_source.to_string()

        event_source_arn = get_event_source_arn(event_source, event, context)
        if event_source_arn:
            trigger_tags["function_trigger.event_source_arn"] = event_source_arn

    if event_source.event_type in [EventTypes.API_GATEWAY, EventTypes.ALB]:
        trigger_tags.update(extract_http_tags(event))

    return trigger_tags


def extract_http_status_code_tag(trigger_tags, response):
    """
    If the Lambda was triggered by API Gateway or ALB add the returned status code
    as a tag to the function execution span.
    """
    is_http_trigger = trigger_tags and (
        trigger_tags.get("function_trigger.event_source") == "api-gateway"
        or trigger_tags.get("function_trigger.event_source")
        == "application-load-balancer"
    )
    if not is_http_trigger:
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
