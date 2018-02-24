#!/usr/bin/python

# -*- coding: utf-8 -*-
#
# (c) 2017, Ben Tomasik <ben@tomasik.io>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible. If not, see <http://www.gnu.org/licenses/>.


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = """
---
module: aws_ses_rule
short_description: Manages SES inbound receipt rules
description:
    - Allows creation, deletion, and management of SES receipt rules
version_added: 2.4
author:
  - "Ben Tomasik (@tomislacker)"
requirements: [ "boto3","botocore" ]
options:
  name:
    description:
      - The name of the receipt rule
    required: True
  ruleset:
    description:
      - The name of the receipt rule set
    required: True
  state:
    description:
      - Whether to create or destroy the receipt rule
    required: False
    default: present
    choices: ["absent", "present"]
  after:
    description:
      - Insert new rule before another (This only applies during creation)
    required: False
  enabled:
    description:
      - Whether the rule should be enabled or not
    required: False
    default: True
  tls_required:
    description:
      - Whether inbound emails should require TLS
    required: False
    default: False
  recipients:
    description:
      - Recipient specification(s)
    required: True
  actions:
    description:
      - Rule actions
    required: True
  scan_enabled:
    description:
      - Whether inbound emails should get virus scanned
    required: False
    default: False
extends_documentation_fragment: aws
"""

EXAMPLES = """

# Pushes emails to S3 that are received for any address @mydomain.com as well
# as any address @<any subdomain>.mydomain.com
- name: Create catch-all rule
  aws_ses_rule:
    name: main-rule
    ruleset: default-rule-set
    recipients:
      - '.mydomain.com'
      - 'mydomain.com'
    actions:
      - S3Action:
          BucketName: my-bucket

"""

RETURN = """
changed:
  description: >
      if a SES rule has been created or deleted. NOTE: If a rule exists, it's
      always considered a change whether or not one occurred due to the lack
      of implementation in change detection.
  returned: success
  type: bool
  sample: true
rules:
  description: >
      The rules that are present after any changes being made by the module.
  returned: success
  type: list
  sample: [TODO]
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


def rule_set_exists(module, ses_client, name):
    rule_sets = call_and_handle_errors(module, ses_client.list_receipt_rule_sets)['RuleSets']
    return any((s for s in rule_sets if s['Name'] == name))


def list_rules(module, ses_client, ruleset):
    return call_and_handle_errors(module, ses_client.describe_receipt_rule_set, RuleSetName=ruleset)['Rules']


def find_rule(module, name, rules):
    matching_rules = [r for r in rules if r['Name'] == name]
    count = len(matching_rules)
    if count == 0:
        return None
    elif count == 1:
        return matching_rules[0]
    else:
        module.fail_json(msg='More than one rule found with name ' + name)


def rule_is_after(name, after, rules):
    return any((i for i, r in enumerate(rules) if r['Name'] == name and i > 0 and rules[i - 1]['Name'] == after))


def replace_rule(new_rule, test_rule):
    if new_rule['Name'] == test_rule['Name']:
        return new_rule
    else:
        return test_rule


def remove_rule(client, module):
    name = module.params.get('name').lower()
    ruleset = module.params.get('ruleset').lower()
    check_mode = module.check_mode

    changed = False
    rules = list_rules(module, client, ruleset)
    existing_rule = find_rule(module, name, rules)
    if exsting_rule is not None:
        if not check_mode:
            call_and_handle_errors(module, client.delete_receipt_rule, RuleSetName=ruleset, RuleName=name)
        changed = True
        rules = [r for r in rules if r['Name'] != name]

    module.exit_json(
        changed=changed,
        rules=[camel_dict_to_snake_dict(r) for f in rules],
    )


def create_or_update_rule(client, module):
    name = module.params.get('name').lower()
    ruleset = module.params.get('ruleset').lower()
    after = module.params.get('after')
    enabled = module.params.get('enabled')
    tls_required = module.params.get('tls_required')
    recipients = module.params.get('recipients')
    actions = module.params.get('actions')
    scan_enabled = module.params.get('scan_enabled')
    check_mode = module.check_mode

    rule_args = {
        'RuleSetName': ruleset,
        'Rule': {
            'Name': name,
            'Enabled': enabled,
            'TlsPolicy': "Require" if tls_required else "Optional",
            'Recipients': recipients,
            'Actions': actions,
            'ScanEnabled': scan_enabled,
        },
    }

    rules = list_rules(module, client, ruleset)
    existing_rule = find_rule(module, name, rules)
    create = existing_rule is None
    recreate = not create and after and not rule_is_after(name, after, rules)

    changed = False
    if create or recreate:
        if after:
            rule_args.update({
                'After': after.lower(),
            })

        if not check_mode:
            if recreate:
                call_and_handle_errors(module, client.delete_receipt_rule, RuleSetName=ruleset, RuleName=name)
            call_and_handle_errors(module, client.create_receipt_rule, **rule_args)
        changed = True

        rules = [r for r in rules if r['Name'] != name]
        if after:
            index = [i for i, r in enumerate(rules) if r['Name'] == after][0] + 1
            rules.insert(index, rule_args)
        else:
            rules.append(rule_args)
    # TODO Check this condition actually works....
    else if existing_rule != rule_args:
        if not check_mode:
            call_and_handle_errors(module, client.update_receipt_rule, **rule_args)
        changed = True
        rules = [replace_rule(rule_args, r) for r in rules]

    module.exit_json(
        changed=changed,
        rules=[camel_dict_to_snake_dict(r) for f in rules],
    )


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
        name=dict(type='str', required=True),
        ruleset=dict(type='str', required=True),
        state=dict(type='str', default='present', choices=['present', 'absent']),
        after=dict(),
        enabled=dict(type='bool', default=True),
        tls_required=dict(type='bool', default=False),
        recipients=dict(type='list', required=True),
        actions=dict(type='list', required=True),
        scan_enabled=dict(type='bool', default=True),
    ))

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           required_if=[
                               ['state', 'present', ['actions', 'recipients']],
                           ])

    state = module.params.get('state').lower()

    if not HAS_BOTO3:
        module.fail_json(msg='Python module "boto3" is missing, please install it')

    region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)
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
    client = boto3_conn(module, conn_type='client', resource='ses', region=region, endpoint=ec2_url, config=boto_core_config, **aws_connect_kwargs)

    ruleset = module.params.get('ruleset').lower()
    if not rule_set_exists(module, client, ruleset):
        module.fail_json(msg='Rule set {} does not exist'.format(ruleset))

    if state == 'absent':
        remove_rule(client, module)
    elif state == 'present':
        create_or_update_rule(client, module)


if __name__ == '__main__':
    main()
