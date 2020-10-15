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

import luigi
from zeta.common.workflow import *

from zeta.dp.zeta.workflows.droplets.bootstrap import *
from zeta.dp.zeta.workflows.droplets.create import *
from zeta.dp.zeta.workflows.droplets.provisioned import *
from zeta.dp.zeta.workflows.droplets.delete import *


class ZetaWorkflowFactory():

    def DropletOperatorStart(self, param):
        return DropletOperatorStart(param=param)

    def DropletCreate(self, param):
        return DropletCreate(param=param)

    def DropletProvisioned(self, param):
        return DropletProvisioned(param=param)

    def DropletDelete(self, param):
        return DropletDelete(param=param)

    def k8sDropletCreate(self, param):
        return k8sDropletCreate(param=param)

    def k8sDropletDelete(self, param):
        return k8sDropletDelete(param=param)
