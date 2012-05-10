# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from keystone.common import wsgi
from keystone.common.wsgi import render_response
from keystone.token import Manager as TokenManager
from keystone.identity import Manager as IdentityManager

def sanitize_dict(dict_to_sanitize, keys_allowed):
    sanitized_dict = {}
    for k,v in dict_to_sanitize.items():
        if k in keys_allowed:
            sanitized_dict[k] = v
    return sanitized_dict

class UserController(wsgi.Application):
    def __init__(self):
        self.identity_manager_api = IdentityManager()
        self.token_manager_api = TokenManager()

    def set_user_password(self, context, user_id, user):
        token_id = context.get("token_id")

        user_ref = self.token_manager_api.get_token(context=context,
            token_id=token_id)
        user_id_from_token = user_ref["user"]["id"]

        if user_id_from_token != user_id:
            return render_response(status=(403,"Not Authorized"),
                body={"error": {"message": "You are not authorized",
                "code": 403, "title": "Not Authorized"}})

        update_dict = sanitize_dict(user, ["id", "password"])

        self.identity_manager_api.update_user(context, user_id, update_dict)

        return render_response(status=(200,"OK"), body={"user":update_dict})


class CrudExtension(wsgi.ExtensionRouter):
    """

    Provides a subset of CRUD operations for internal data types.

    """

    def add_routes(self, mapper):
        user_controller = UserController()

        # COMPAT(diablo): the copy with no OS-KSADM is from diablo
        mapper.connect('/users/{user_id}/password',
                    controller=user_controller,
                    action='set_user_password',
                    conditions=dict(method=['PUT']))
        mapper.connect('/users/{user_id}/OS-KSADM/password',
                    controller=user_controller,
                    action='set_user_password',
                    conditions=dict(method=['PUT']))

