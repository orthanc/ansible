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
version_added: 2.7
author:
  - "Ed Costello (@orthanc)"
requirements: [ "boto3","botocore" ]
options:
  name:
    description:
      - The name of the receipt rule set to gather facts for. If omitted then only the list of rule sets is returned.
extends_documentation_fragment:
    - aws
    - ec2
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
"""

from ansible.module_utils.aws.core import AnsibleAWSModule
from ansible.module_utils.ec2 import camel_dict_to_snake_dict, AWSRetry

try:
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:
    pass  # handled by AnsibleAWSModule


def list_rule_sets(client, module):
    try:
        return client.list_receipt_rule_sets(aws_retry=True)['RuleSets']
    except (BotoCoreError, ClientError) as e:
        module.fail_json_aws(e, msg="Couldn't list rule sets.")


def get_active_rule_set(client, module):
    try:
        active_rule_set = client.describe_active_receipt_rule_set(aws_retry=True)
    except (BotoCoreError, ClientError) as e:
        module.fail_json_aws(e, msg="Couldn't get the active rule set.")
    if active_rule_set is not None and 'Metadata' in active_rule_set:
        return active_rule_set
    else:
        return None


def get_rule_set(client, module, name):
    try:
        return client.describe_receipt_rule_set(RuleSetName=name, aws_retry=True)
    except (BotoCoreError, ClientError) as e:
        module.fail_json_aws(e, msg="Couldn't get rule set {0}.".format(name))


def main():
    module = AnsibleAWSModule(
        argument_spec=dict(
            name=dict(type='str'),
        ),
        supports_check_mode=True,
    )

    # SES APIs seem to have a much lower throttling threshold than most of the rest of the AWS APIs.
    # Docs say 1 call per second. This shouldn't actually be a big problem for normal usage, but
    # the ansible build runs multiple instances of the test in parallel that's caused throttling
    # failures so apply a jittered backoff to call SES calls.
    client = module.client('ses', retry_decorator=AWSRetry.jittered_backoff())

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
