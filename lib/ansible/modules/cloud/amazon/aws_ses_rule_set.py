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
module: aws_ses_rule_set
short_description: Manages SES inbound receipt rule sets
description:
    - The M(aws_ses_rule_set) module allows you to create, delete, and manage SES receipt rule sets
version_added: 2.6
author:
  - "Ben Tomasik (@tomislacker)"
requirements: [ "boto3","botocore" ]
options:
  name:
    description:
      - The name of the receipt rule set.
    required: True
  state:
    description:
      - Whether to create (or update) or destroy the receipt rule set.
    required: False
    default: present
    choices: ["absent", "present"]
  active:
    description:
      - Whether or not this rule set should be the active rule set. Only has an impact if I(state) is C(present).
      - If omitted, the active rule set will not be changed.
      - If C(True) then this rule set will be made active and all others inactive.
      - if C(False) then this rule set will be deactivated. Be careful with this as you can end up with no active rule set.
    type: bool
    required: False
  force:
    description:
      - When deleting a rule set, deactivate it first (AWS prevents deletion of the active rule set).
    type: bool
    required: False
    default: False
extends_documentation_fragment: aws
"""

EXAMPLES = """
# Note: None of these examples set aws_access_key, aws_secret_key, or region.
# It is assumed that their matching environment variables are set.
---
- name: Create default rule set and activate it if not already
  aws_ses_rule_set:
    name: default-rule-set
    active: yes

- name: Create some arbitrary rule set but do not activate it
  aws_ses_rule_set:
    name: arbitrary-rule-set

- name: Explicitly deactivate the default rule set leaving no active rule set
  aws_ses_rule_set:
    name: default-rule-set
    active: no
"""

RETURN = """
changed:
  description: if a SES rule set has been created and/or activated, or deleted
  returned: success
  type: bool
  sample: true
active:
  description: if the SES rule set is active
  returned: success if I(state) is C(present)
  type: bool
  sample: true
rule_sets:
  description: The list of SES receipt rule sets that exist after any changes.
  returned: success
  type: list
  sample: [{
      "created_timestamp": "2018-02-25T01:20:32.690000+00:00",
      "name": "default-rule-set"
    }]

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


def rule_set_in(name, rule_sets):
    return any([s for s in rule_sets if s['Name'] == name])


def update_active_rule_set(client, module, name, desired_active):
    check_mode = module.check_mode

    active_rule_set = call_and_handle_errors(module, client.describe_active_receipt_rule_set)
    if active_rule_set is not None and 'Metadata' in active_rule_set:
        active = name == active_rule_set['Metadata']['Name']
    else:
        # Metadata was not set meaning there is no active rule set
        active = False

    changed = False
    if desired_active is not None:
        if desired_active and not active:
            if not check_mode:
                call_and_handle_errors(module, client.set_active_receipt_rule_set, RuleSetName=name)
            changed = True
            active = True
        elif not desired_active and active:
            if not check_mode:
                call_and_handle_errors(module, client.set_active_receipt_rule_set)
            changed = True
            active = False
    return changed, active


def create_or_update_rule_set(client, module):
    name = module.params.get('name')
    check_mode = module.check_mode
    changed = False

    rule_sets = list_rule_sets(client, module)
    if not rule_set_in(name, rule_sets):
        if not check_mode:
            call_and_handle_errors(module, client.create_receipt_rule_set, RuleSetName=name)
        changed = True
        rule_sets = list(rule_sets)
        rule_sets.append({
            'Name': name,
        })

    (active_changed, active) = update_active_rule_set(client, module, name, module.params.get('active'))
    changed |= active_changed

    module.exit_json(
        changed=changed,
        active=active,
        rule_sets=[camel_dict_to_snake_dict(x) for x in rule_sets],
    )


def remove_rule_set(client, module):
    name = module.params.get('name')
    check_mode = module.check_mode
    changed = False

    rule_sets = list_rule_sets(client, module)
    if rule_set_in(name, rule_sets):
        if not check_mode:
            if module.params.get('force'):
                update_active_rule_set(client, module, name, False)
            call_and_handle_errors(module, client.delete_receipt_rule_set, RuleSetName=name)
        changed = True
        rule_sets = [x for x in rule_sets if x['Name'] != name]

    module.exit_json(
        changed=changed,
        rule_sets=[camel_dict_to_snake_dict(x) for x in rule_sets],
    )


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
        name=dict(type='str', required=True),
        state=dict(type='str', default='present', choices=['present', 'absent']),
        active=dict(type='bool'),
        force=dict(type='bool', default=False),
    ))

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)

    state = module.params.get('state')

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

    if state == 'absent':
        remove_rule_set(client, module)
    else:
        create_or_update_rule_set(client, module)


if __name__ == '__main__':
    main()
