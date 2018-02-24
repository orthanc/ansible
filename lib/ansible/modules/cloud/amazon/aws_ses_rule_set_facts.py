#!/usr/bin/python
# Copyright (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = """
---
module: aws_ses_rule_set_facts
short_description: Retrieve facts for AWS SES receipt rule sets,
description:
    - The M(aws_ses_rule_set_facts) module allows you retrieve the details of what SES
      receipt rule sets exist, what rules are in them and which is active.
version_added: 2.6
author:
  - "Ed Costello (@orthanc)"
requirements: [ "boto3","botocore" ]
options:
  name:
    description:
      - The name of the receipt rule set to gather facts for. If omitted then only the list of rule sets is returned.
extends_documentation_fragment: aws
"""

EXAMPLES = """
# Note: None of these examples set aws_access_key, aws_secret_key, or region.

- name: Retrieve Just the List of Rule Sets
  aws_ses_rule_set_facts:

- name: Retrieve Facts for Default Rule Set
  aws_ses_rule_set_facts:
    name: default-rule-set
"""

RETURN = """
rule_sets:
    description: The list of all receipt rule sets that currently exist for the account / region.
    returned: always
    type: list
    sample: [{
        "created_timestamp": "2018-02-25T02:09:01.493000+00:00",
        "name": "ansible-test-lapserver-32593459-default-rule-set"
      }]
active_rule_set:
    description: The details of the currently active rule set. May be C(None) if there is no rule set currently active.
    returned: always
    type: complex
    sample: {
        "metadata": {
          "created_timestamp": "2018-02-25T02:09:01.493000+00:00",
          "name": "default-rule-set"
        },                                                                                                                               "response_metadata": {
        "rules": []
      }
rule_set:
    description: The details of the rule set specified with I(name).
    returned: if I(name) is specified
    type: complex
    sample: {
        "metadata": {
          "created_timestamp": "2018-02-25T02:09:01.493000+00:00",
          "name": "default-rule-set"
        },                                                                                                                               "response_metadata": {
        "rules": []
      }
error:
    description: The details of the error response from AWS.
    returned: on client error from AWS
    type: complex
    sample: {
        "code": "InvalidParameterValue",
        "message": "Feedback notification topic is not set.",
        "type": "Sender"
    }
    contains:
        code:
            description: The AWS error code.
            type: string
        message:
            description: The AWS error message.
            type: string
        type:
            description: The AWS error type.
            type: string
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ec2 import HAS_BOTO3
from ansible.module_utils.ec2 import ec2_argument_spec
from ansible.module_utils.ec2 import get_aws_connection_info
from ansible.module_utils.ec2 import camel_dict_to_snake_dict
from ansible.module_utils.ec2 import boto3_conn

import traceback

try:
    from botocore.exceptions import BotoCoreError, ClientError
    from botocore.config import Config
except ImportError:
    pass  # caught by imported HAS_BOTO3


def call_and_handle_errors(module, method, **kwargs):
    try:
        return method(**kwargs)
    except ClientError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc(),
                         **camel_dict_to_snake_dict(e.response))
    except BotoCoreError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


def list_rule_sets(client, module):
    response = call_and_handle_errors(module, client.list_receipt_rule_sets)
    return response['RuleSets']


def get_active_rule_set(client, module):
    active_rule_set = call_and_handle_errors(module, client.describe_active_receipt_rule_set)
    if active_rule_set is not None and 'Metadata' in active_rule_set:
        return active_rule_set
    else:
        return None


def get_rule_set(client, module, name):
    return call_and_handle_errors(module, client.describe_receipt_rule_set, RuleSetName=name)


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
        name=dict(type='str'),
    ))

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    if not HAS_BOTO3:
        module.fail_json(msg='Python module "boto3" is missing, please install it')

    region, ec2_url, aws_connect_params = get_aws_connection_info(module, boto3=True)
    if not region:
        module.fail_json(msg='region must be specified')

    # Allow up to 10 attempts to call the SES APIs before giving up (9 retries).
    # SES APIs seem to have a much lower throttling threshold than most of the rest of the AWS APIs.
    # Docs say 1 call per second. This shouldn't actually be a big problem for normal usage, but
    # the ansible build runs multiple instances of the test in parallel.
    # As a result there are build failures due to throttling that exceeds boto's default retries.
    # The back-off is exponential, so upping the retry attempts allows multiple parallel runs
    # to succeed.
    boto_core_config = Config(retries={'max_attempts': 9})
    client = boto3_conn(module, conn_type='client', resource='ses', region=region, endpoint=ec2_url, config=boto_core_config, **aws_connect_params)

    name = module.params.get('name')

    rule_sets = list_rule_sets(client, module)
    active_rule_set = get_active_rule_set(client, module)

    if name is not None:
        if active_rule_set is not None and name == active_rule_set['Metadata']['Name']:
            rule_set = active_rule_set
        else:
            rule_set = get_rule_set(client, module, name)
    else:
        rule_set = None

    facts = {
        'rule_sets': [camel_dict_to_snake_dict(r) for r in rule_sets],
    }
    if active_rule_set is not None:
        facts['active_rule_set'] = camel_dict_to_snake_dict(active_rule_set)
    else:
        facts['active_rule_set'] = None

    if rule_set is not None:
        facts['rule_set'] = camel_dict_to_snake_dict(rule_set)

    module.exit_json(
        changed=False,
        **facts
    )


if __name__ == '__main__':
    main()
