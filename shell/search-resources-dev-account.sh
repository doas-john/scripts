#!/bin/bash

aws resource-explorer-2 search --query-string \
"region:us-east-1 \
 -service:acm \
 -service:access-analyzer \
 -service:appflow \
 -service:app-integrations \
 -service:athena \
 -service:backup \
 -service:cloudformation \
 -service:cloudtrail \
 -service:cloudwatch \
 -service:connect \
 -service:ecs \
 -service:events \
 -service:geo \
 -service:glue \
 -service:guardduty \
 -service:kinesis \
 -service:kinesisvideo \
 -service:kms \
 -service:lambda \
 -service:lex \
 -service:logs \
 -service:memorydb \
 -service:mobiletargeting \
 -service:pipes \
 -service:quicksight \
 -service:ram \
 -service:resource-explorer-2 \
 -service:resource-groups \
 -service:ses \
 -service:sns \
 -service:sqs \
 -service:ssm \
 -service:states \
 -service:wisdom"
