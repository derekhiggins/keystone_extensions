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

import webob
import webob.dec
import webob.exc


class UserController(object):

    def __init__(self):
        self.identity_manager_api = IdentityManager()
        self.token_manager_api = TokenManager()

    @webob.dec.wsgify
    def __call__(self, req):

        try:
            # Get the User id from the token id
            token_id = req.headers.get("X-Auth-Token")
            user = self.token_manager_api.get_token(context=req, token_id=token_id)
            user_id = user["user"]["id"]

            params = req.environ.get('openstack.params', {})

            req_user_id = params["user"]["id"]
            req_user_passwd = params["user"]["password"]
        except:
            return render_response(status=(500,"Internal Server Error"),
                body={"error": {"message": "Unexpected Error", "code": 500,
                "title": "Internal Server Error"}})

        # test if the request is trying to change somebody elses password
        if user_id != req_user_id:
            return render_response(status=(403,"Not Authorized"),
                body={"error": {"message": "You are not authorized",
                "code": 403, "title": "Not Authorized"}})

        try:
            user_ref = self.identity_manager_api.update_user(req, user_id, params["user"])
        except:
            return render_response(status=(500,"Internal Server Error"),
                body={"error": {"message": "Unexpected Error", "code": 500,
                "title": "Internal Server Error"}})

        return render_response(status=(200,"OK"), body={"user":user_ref})

class CrudExtension(wsgi.ExtensionRouter):
    """

    Provides a subset of CRUD operations for internal data types.

    """

    def add_routes(self, mapper):
        user_controller = UserController()

        # COMPAT(diablo): the copy with no OS-KSADM is from diablo
        mapper.connect('/users/{user_id}/password',
                    controller=user_controller,
                    conditions=dict(method=['PUT']))
        mapper.connect('/users/{user_id}/OS-KSADM/password',
                    controller=user_controller,
                    conditions=dict(method=['PUT']))

