# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.

import base64
import gzip
import json
from io import BytesIO, BufferedReader


EVENT_SOURCES = {
    "aws:dynamodb",
    "aws:kinesis",
    "aws:s3",
    "aws:sns",
    "aws:sqs",
}


def get_first_record(event):
    records = event.get("Records")
    if records and len(records) > 0:
        return records[0]


def get_event_source(event):
    """Determines the source of the trigger event

    Possible Returns:
        api-gateway | application-load-balancer | cloudwatch-logs |
        cloudwatch-events | cloudfront | dynamodb | kinesis | s3 | sns | sqs
    """
    event_source = event.get("eventSource") or event.get("EventSource")

    request_context = event.get("requestContext")
    if request_context and request_context.get("stage"):
        event_source = "api-gateway"

    if request_context and request_context.get("elb"):
        event_source = "application-load-balancer"

    if event.get("awslogs"):
        event_source = "cloudwatch-logs"

    event_detail = event.get("detail")
    cw_event_categories = event_detail and event_detail.get("EventCategories")
    if event.get("source") == "aws.events" or cw_event_categories:
        event_source = "cloudwatch-events"

    event_record = get_first_record(event)
    if event_record:
        event_source = event_record.get("eventSource") or event_record.get(
            "EventSource"
        )
        if event_record.get("cf"):
            event_source = "cloudfront"

    if event_source in EVENT_SOURCES:
        event_source = event_source.replace("aws:", "")
    return event_source


def parse_event_source_arn(source, event, context):
    """
    Parses the trigger event for an available ARN. If an ARN field is not provided
    in the event we stitch it together.
    """
    split_function_arn = context.invoked_function_arn.split(":")
    region = split_function_arn[3]
    account_id = split_function_arn[4]

    event_record = get_first_record(event)
    # e.g. arn:aws:s3:::lambda-xyz123-abc890
    if source == "s3":
        return event_record.get("s3")["bucket"]["arn"]

    # e.g. arn:aws:sns:us-east-1:123456789012:sns-lambda
    if source == "sns":
        return event_record.get("Sns")["TopicArn"]

    # e.g. arn:aws:cloudfront::123456789012:distribution/ABC123XYZ
    if source == "cloudfront":
        distribution_id = event_record.get("cf")["config"]["distributionId"]
        return "arn:aws:cloudfront::{}:distribution/{}".format(
            account_id, distribution_id
        )

    # e.g. arn:aws:apigateway:us-east-1::/restapis/xyz123/stages/default
    if source == "api-gateway":
        request_context = event.get("requestContext")
        return "arn:aws:apigateway:{}::/restapis/{}/stages/{}".format(
            region, request_context["apiId"], request_context["stage"]
        )

    # e.g. arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/lambda-xyz/123
    if source == "application-load-balancer":
        request_context = event.get("requestContext")
        return request_context.get("elb")["targetGroupArn"]

    # e.g. arn:aws:logs:us-west-1:123456789012:log-group:/my-log-group-xyz
    if source == "cloudwatch-logs":
        with gzip.GzipFile(
            fileobj=BytesIO(base64.b64decode(event["awslogs"]["data"]))
        ) as decompress_stream:
            data = b"".join(BufferedReader(decompress_stream))
        logs = json.loads(data)
        log_group = logs.get("logGroup", "cloudwatch")
        return "arn:aws:logs:{}:{}:log-group:{}".format(region, account_id, log_group)

    # e.g. arn:aws:events:us-east-1:123456789012:rule/my-schedule
    if source == "cloudwatch-events" and event.get("resources"):
        return event.get("resources")[0]


def get_event_source_arn(source, event, context):
    event_source_arn = event.get("eventSourceARN") or event.get("eventSourceArn")

    event_record = get_first_record(event)
    if event_record:
        event_source_arn = event_record.get("eventSourceARN") or event_record.get(
            "eventSourceArn"
        )

    if event_source_arn is None:
        event_source_arn = parse_event_source_arn(source, event, context)

    return event_source_arn


def get_http_tags(event):
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


def extract_trigger_tags(event, context):
    """
    Parses the trigger event object to get tags to be added to the span metadata
    """
    trigger_tags = {}
    event_source = get_event_source(event)
    if event_source:
        trigger_tags["trigger.event_source"] = event_source

        event_source_arn = get_event_source_arn(event_source, event, context)
        if event_source_arn:
            trigger_tags["trigger.event_source_arn"] = event_source_arn

    if event_source in ["api-gateway", "application-load-balancer"]:
        trigger_tags.update(get_http_tags(event))

    return trigger_tags


def set_http_status_code_tag(span, response):
    """
    If the Lambda was triggered by API Gateway add the returned status code
    as a tag to the function execution span
    """
    is_apigateway_trigger = (
        span and span.get_tag("trigger.event_source") == "api-gateway"
    )
    if is_apigateway_trigger and response and response.get("statusCode"):
        span.set_tag("http.status_code", response.get("statusCode"))