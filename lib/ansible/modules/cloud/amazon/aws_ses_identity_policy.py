#!/usr/bin/python
# Copyright (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: aws_ses_identity_policy
short_description: Manages SES sending authorization policies
description:
    - This module allows the user to manage sending authorization policies associated with an SES identity (email or domain).
    - SES authorization sending policies can be used to control what actors are able to send email
      on behalf of the validated identity and what conditions must be met by the sent emails.
version_added: "2.6"
author: Ed Costello    (@orthanc)

options:
    identity:
        description: |
            The SES identity to attach or remove a policy from. This can be either the full ARN or just
            the verified email or domain.
        required: true
    policy_name:
        description: The name used to identify the policy within the scope of the identity it's attached to.
        required: true
    policy:
        description: A properly formated JSON sending authorization policy. Required when I(state=present).
    state:
        description: Whether to create(or update) or delete the authorization policy on the identity.
        default: present
        choices: [ 'present', 'absent' ]
requirements: [ 'botocore', 'boto3' ]
extends_documentation_fragment:
    - aws
    - ec2
'''

EXAMPLES = '''
# Note: These examples do not set authentication details, see the AWS Guide for details.

- name: add sending authorization policy to domain identity
  aws_ses_identity_policy:
    identity: example.com
    policy_name: ExamplePolicy
    policy: "{{ lookup('template', 'policy.json.j2') }}"
    state: present

- name: add sending authorization policy to email identity
  aws_ses_identity_policy:
    identity: example@example.com
    policy_name: ExamplePolicy
    policy: "{{ lookup('template', 'policy.json.j2') }}"
    state: present

- name: add sending authorization policy to identity using ARN
  aws_ses_identity_policy:
    identity: "arn:aws:ses:us-east-1:12345678:identity/example.com"
    policy_name: ExamplePolicy
    policy: "{{ lookup('template', 'policy.json.j2') }}"
    state: present

- name: remove sending authorization policy
  aws_ses_identity_policy:
    identity: example.com
    policy_name: ExamplePolicy
    state: absent
'''

RETURN = '''
policies:
    description: A list of all policies present on the identity after the operation.
    returned: success
    type: list
    sample: [ExamplePolicy]
error:
    description: The details of the error response from AWS.
    returned: on client error from AWS
    type: complex
    sample: {
        "code": "InvalidPolicy",
        "message": "Unable to parse policy.",
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
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ec2 import (ec2_argument_spec, get_aws_connection_info, boto3_conn,
                                      camel_dict_to_snake_dict, sort_json_policy_dict)
from ansible.module_utils.ec2 import HAS_BOTO3

import json
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


def get_identity_policy(connection, module, identity, policy_name):
    response = call_and_handle_errors(module, connection.get_identity_policies, Identity=identity, PolicyNames=[policy_name])
    policies = response['Policies']
    if policy_name in policies:
        return policies[policy_name]
    return None


def create_or_update_identity_policy(connection, module):
    identity = module.params.get('identity')
    policy_name = module.params.get('policy_name')
    required_policy = module.params.get('policy')
    required_policy_dict = sort_json_policy_dict(json.loads(required_policy))

    changed = False
    policy = get_identity_policy(connection, module, identity, policy_name)
    policy_dict = sort_json_policy_dict(json.loads(policy)) if policy else None
    if required_policy_dict != policy_dict:
        changed = True
        call_and_handle_errors(module, connection.put_identity_policy, Identity=identity, PolicyName=policy_name, Policy=required_policy)

    # Load the list of applied policies to include in the response.
    # In principle we should be able to just return the response, but given
    # eventual consistency behaviours in AWS it's plausible that we could
    # end up with a list that doesn't contain the policy we just added.
    # So out of paranoia check for this case and if we're missing the policy
    # just make sure it's present.
    policies_present = call_and_handle_errors(module, connection.list_identity_policies, Identity=identity)['PolicyNames']
    if policy_name is not None and policy_name not in policies_present:
        policies_present = list(policies_present)
        policies_present.append(policy_name)
    module.exit_json(
        changed=changed,
        policies=policies_present,
    )


def delete_identity_policy(connection, module):
    identity = module.params.get('identity')
    policy_name = module.params.get('policy_name')

    changed = False
    policies_present = call_and_handle_errors(module, connection.list_identity_policies, Identity=identity)['PolicyNames']
    if policy_name in policies_present:
        call_and_handle_errors(module, connection.delete_identity_policy, Identity=identity, PolicyName=policy_name)
        changed = True
        policies_present = list(policies_present)
        policies_present.remove(policy_name)

    module.exit_json(
        changed=changed,
        policies=policies_present,
    )


def main():
    argument_spec = ec2_argument_spec()

    argument_spec.update(
        dict(
            identity=dict(required=True, type='str'),
            state=dict(default='present', choices=['present', 'absent']),
            policy_name=dict(required=True, type='str'),
            policy=dict(type='json', default=None),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=[['state', 'present', ['policy']]]
    )

    if not HAS_BOTO3:
        module.fail_json(msg='boto3 required for this module')

    region, ec2_url, aws_connect_params = get_aws_connection_info(module, boto3=True)

    # Allow up to 10 attempts to call the SES APIs before giving up (9 retries).
    # SES APIs seem to have a much lower throttling threshold than most of the rest of the AWS APIs.
    # Docs say 1 call per second. This shouldn't actually be a big problem for normal usage, but
    # the ansible build runs multiple instances of the test in parallel.
    # As a result there are build failures due to throttling that exceeds boto's default retries.
    # The back-off is exponential, so upping the retry attempts allows multiple parallel runs
    # to succeed.
    boto_core_config = Config(retries={'max_attempts': 9})
    connection = boto3_conn(module, conn_type='client', resource='ses', region=region, endpoint=ec2_url, config=boto_core_config, **aws_connect_params)

    state = module.params.get("state")

    if state == 'present':
        create_or_update_identity_policy(connection, module)
    else:
        delete_identity_policy(connection, module)


if __name__ == '__main__':
    main()
