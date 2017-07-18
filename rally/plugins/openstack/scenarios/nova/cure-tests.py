# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import six
import requests
import json

from requests_kerberos import HTTPKerberosAuth

from rally.common import logging
from rally.common.i18n import _
from rally import consts
from rally import exceptions
from rally.plugins.openstack import scenario
from rally.plugins.openstack.scenarios.nova import utils as nova_utils
from rally.plugins.openstack.scenarios.cinder import utils as cinder_utils
from rally.task import atomic
from rally.task import types
from rally.task import validation
from rally.task import scenario

LOG = logging.getLogger(__name__)

class NovaSecurityGroupException(exceptions.RallyException):
    msg_fmt = _("%(message)s")

class NovaGDC(nova_utils.NovaScenario):
    """Benchmark scenarios for GDC purposes."""

    @types.convert(image={"type": "glance_image"},
                   flavor={"type": "nova_flavor"})
    @validation.image_valid_on_flavor("flavor", "image")
    @validation.required_parameters("security_group_count",
                                    "rules_per_security_group")
#    @validation.required_contexts("network")
    @validation.required_services(consts.Service.NOVA)
    @validation.required_openstack(users=True)
    @scenario.configure(context={"cleanup": ["nova"]})
    def boot_and_delete_server_with_secgroups_sleep(self, image, flavor,
                                              security_group_count,
                                              rules_per_security_group,
                                              min_sleep=0, max_sleep=0,
                                              **kwargs):
        """Boot and delete server with security groups attached.

        Plan of this scenario:
         - create N security groups with M rules per group
           vm with security groups)
         - boot a VM with created security groups
         - get list of attached security groups to server
         - delete server
         - delete all security groups
         - check that all groups were attached to server

        :param min_sleep: Minimum sleep time in seconds (non-negative)
        :param max_sleep: Maximum sleep time in seconds (non-negative)
        :param image: ID of the image to be used for server creation
        :param flavor: ID of the flavor to be used for server creation
        :param security_group_count: Number of security groups
        :param rules_per_security_group: Number of rules per security group
        :param **kwargs: Optional arguments for booting the instance
        """

        security_groups = self._create_security_groups(
            security_group_count)
        self._create_rules_for_security_group(security_groups,
                                              rules_per_security_group)

        secgroups_names = [sg.name for sg in security_groups]
        server = self._boot_server(image, flavor,
                                   security_groups=secgroups_names,
                                   **kwargs)

        action_name = "nova.get_attached_security_groups"
        with atomic.ActionTimer(self, action_name):
            attached_security_groups = server.list_security_group()

        self.sleep_between(min_sleep, max_sleep)
        self._delete_server(server)
        try:
            self._delete_security_groups(security_groups)
        except Exception as e:
            if hasattr(e, "http_status") and e.http_status == 400:
                raise NovaSecurityGroupException(six.text_type(e))
            raise

        error_message = ("Expected number of attached security groups to "
                         " server %(server)s is '%(all)s', but actual number "
                         "is '%(attached)s'." % {
                             "attached": len(attached_security_groups),
                             "all": len(security_groups),
                             "server": server})

        self.assertEqual(sorted([sg.id for sg in security_groups]),
                         sorted([sg.id for sg in attached_security_groups]),
                         error_message)

class ForemanGDC(nova_utils.NovaScenario, cinder_utils.CinderScenario):
    """Benchmark scenarios for GDC purposes."""

    def _check_request(self, url, method, status_code, **kwargs):
        """Compare request status code with specified code

        :param status_code: Expected status code of request
        :param url: Uniform resource locator
        :param method: Type of request method (GET | POST ..)
        :param kwargs: Optional additional request parameters
        :raises ValueError: if return http status code
                            not equal to expected status code
        """

        resp = requests.request(method, url, **kwargs)
        LOG.info("ITER: %s Foreman response: %s" % (self.context["iteration"], resp.text))
        if status_code != resp.status_code:
            error_msg = _("Expected HTTP request code is `%s` actual `%s`")
            raise ValueError(
                error_msg % (status_code, resp.status_code))
        return resp

    class Server(object):
      """Fake server class to define servers deployed via Foreman API"""
      def __init__(self, id):
        self.id = id

    def make_server(self, id):
      server = self.Server(id)
      return server

    @validation.required_parameters("host_prefix", "host_domain", "payload")
    @scenario.configure()
    def boot_and_delete_server(self, url, host_prefix, host_domain, payload, min_sleep=0, max_sleep=0, **kwargs):
        """Standard way to benchmark web services.

        This benchmark is used to make request and check it with expected
        Response.

        :param url: url for the Request object
        :param method: method for the Request object
        :param status_code: expected response code
        :param kwargs: optional additional request parameters
        """

        for key in kwargs:
          print "another keyword arg: %s: %s" % (key, kwargs[key])

        with open(payload) as pf:
          data = json.load(pf)
        headers = {'Content-Type' : 'application/json'}
        host = host_prefix + str(self.context["iteration"])
        data['name'] = host
        data['compute_attributes']['availability_zone'] = kwargs['availability_zone']
        for attrib in data['host_parameters_attributes']:
          if attrib['name'] == 'hostname':
            attrib['value'] = host

        action_name = "foreman.create_host"
        with atomic.ActionTimer(self, action_name):
          LOG.info('Create instance ' + host + ' via Foreman: ' + str(json.dumps(data)))
          resp = self._check_request(url, 'POST', 201, json=data, auth=HTTPKerberosAuth(), allow_redirects=kwargs['allow_redirects'])
          respjson = resp.json()
          LOG.info("Server UUID: %s" % respjson['uuid'])

        LOG.info('Waiting for ' + str(min_sleep) + ' - ' + str(max_sleep) + ' seconds')
        self.sleep_between(min_sleep, max_sleep)

        action_name = "foreman.delete_host"
        with atomic.ActionTimer(self, action_name):
          LOG.info('Delete instance via Foreman: ' + url + '/' + host + host_domain)
          self._check_request(url + '/' + host + host_domain, 'DELETE', 200, auth=HTTPKerberosAuth(), allow_redirects=kwargs['allow_redirects'])

    @validation.required_services(consts.Service.NOVA, consts.Service.CINDER)
    @validation.required_openstack(users=True)
    @scenario.configure()
    def boot_and_delete_server_volume(self, url, host_prefix, host_domain, payload, volume_size, min_sleep=0, max_sleep=0, **kwargs):
        """
        Create volume, boot server, attach volume, destroy server, destroy volume
        """
        iteration = self.context["iteration"]
        max_per_zone = kwargs['max_per_zone']
        availability_zone_list = kwargs['availability_zone']
        availability_zone = availability_zone_list[iteration // max_per_zone]

        #delay between deploys
        deploy_delay = kwargs['deploy_delay'] * iteration
        LOG.info("ITER: %s Wait for %s seconds before start" % (iteration, deploy_delay))
        self.sleep_between(deploy_delay, deploy_delay)

        LOG.info("ITER: %s Create volume in AV zone '%s' with size '%s'" % (iteration, availability_zone, volume_size))
        volume = self._create_volume(volume_size, availability_zone=availability_zone)
        LOG.info("ITER: %s Volume id: %s" % (iteration, volume.id))

        action_name = "foreman.create_host"
        with open(payload) as pf:
          data = json.load(pf)
        headers = {'Content-Type' : 'application/json'}
        host = host_prefix + str(iteration)
        data['name'] = host
        data['compute_attributes']['availability_zone'] = availability_zone
        data['compute_attributes']['flavor_id'] = kwargs['flavor_id']
        data['compute_attributes']['flavor_ref'] = kwargs['flavor_id']
        for attrib in data['host_parameters_attributes']:
          if attrib['name'] == 'hostname':
            attrib['value'] = host
        with atomic.ActionTimer(self, action_name):
          LOG.info("ITER: %s Create instance %s via Foreman in '%s': %s" % (iteration, host, availability_zone, json.dumps(data)))
          resp = self._check_request(url, 'POST', 201, json=data, auth=HTTPKerberosAuth(), allow_redirects=kwargs['allow_redirects'])
          respjson = resp.json()

        server = self.make_server(respjson['uuid']) # fake server object
        LOG.info("ITER: %s Attach volume '%s' to instance '%s'" % (iteration, volume.id, server.id))
        self._attach_volume(server, volume)

        LOG.info("ITER: %s Waiting for %s seconds" % (iteration, max_sleep))
        self.sleep_between(min_sleep, max_sleep)

        LOG.info("ITER: %s Detach volume '%s' from instance '%s'" % (iteration, volume.id, server.id))
        self._detach_volume(server, volume)

        self.sleep_between(5, 5)

        action_name = "foreman.delete_host"
        with atomic.ActionTimer(self, action_name):
          LOG.info("ITER: %s Delete instance via Foreman: %s/%s%s" % (iteration, url, host, host_domain))
          self._check_request(url + '/' + host + host_domain, 'DELETE', 200, auth=HTTPKerberosAuth(), allow_redirects=kwargs['allow_redirects'])

        LOG.info ("ITER: %s Delete volume '%s'" % (iteration, volume.id))
        self._delete_volume(volume)
