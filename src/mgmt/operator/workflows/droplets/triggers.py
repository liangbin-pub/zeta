# SPDX-License-Identifier: MIT
# Copyright (c) 2020 The Authors.

# Authors: Sherif Abdelwahab <@zasherif>
#          Phu Tran          <@phudtran>

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:The above copyright
# notice and this permission notice shall be included in all copies or
# substantial portions of the Software.THE SOFTWARE IS PROVIDED "AS IS",
# WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
# TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
# FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR
# THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import kopf
import logging
import asyncio
from common.common import *
from common.constants import *
from common.wf_factory import *
from common.wf_param import *
from workflows.droplets.create import *
from workflows.droplets.delete import *
from workflows.droplets.provisioned import *


@kopf.on.resume(group, version, RESOURCES.droplets, when=LAMBDAS.status_init, retries=OBJ_DEFAULTS.kopf_max_retries)
@kopf.on.update(group, version, RESOURCES.droplets, when=LAMBDAS.status_init, retries=OBJ_DEFAULTS.kopf_max_retries)
@kopf.on.create(group, version, RESOURCES.droplets, when=LAMBDAS.status_init, retries=OBJ_DEFAULTS.kopf_max_retries)
def droplet_opr_on_droplet_init(body, spec, **kwargs):
    param = HandlerParam()
    param.name = kwargs['name']
    param.body = body
    param.spec = spec
    param.workflow_func = droplet_create
    run_workflow(wffactory().CommonCreate(param=param))


@kopf.on.resume(group, version, RESOURCES.droplets, when=LAMBDAS.status_provisioned, retries=OBJ_DEFAULTS.kopf_max_retries)
@kopf.on.update(group, version, RESOURCES.droplets, when=LAMBDAS.status_provisioned, retries=OBJ_DEFAULTS.kopf_max_retries)
@kopf.on.create(group, version, RESOURCES.droplets, when=LAMBDAS.status_provisioned, retries=OBJ_DEFAULTS.kopf_max_retries)
def droplet_opr_on_droplet_provisioned(body, spec, **kwargs):
    param = HandlerParam()
    param.name = kwargs['name']
    param.body = body
    param.spec = spec
    param.workflow_func = droplet_provisioned
    run_workflow(wffactory().CommonProvisioned(param=param))


@kopf.on.delete(group, version, RESOURCES.droplets, retries=OBJ_DEFAULTS.kopf_max_retries)
def droplet_opr_on_droplet_delete(body, spec, **kwargs):
    param = HandlerParam()
    param.name = kwargs['name']
    param.body = body
    param.spec = spec
    param.workflow_func = droplet_delete
    run_workflow(wffactory().CommonDelete(param=param))
