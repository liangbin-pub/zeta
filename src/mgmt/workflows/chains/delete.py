# SPDX-License-Identifier: MIT
# Copyright (c) 2020 The Authors.

# Authors: Phu Tran          <@phudtran>

import logging
from common.workflow import *
from operators.chains_operator import *

logger = logging.getLogger()
chains_opr = ChainOperator()


class ChainDelete(WorkflowTask):

    def requires(self):
        logger.info("Requires {task}".format(task=self.__class__.__name__))
        return []

    def run(self):
        logger.info("Run {task}".format(task=self.__class__.__name__))
        chain = chains_opr.store_get_obj(
            self.param.name, self.param.spec["plural"], self.param.spec)

        chains_opr.store_delete_obj(chain.name, chain.resource)
        self.finalize()
