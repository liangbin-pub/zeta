# SPDX-License-Identifier: MIT
# Copyright (c) 2020 The Authors.
#
# Authors: Bin Liang <@liangbin>
#
# Summary: Port table for NBI API
#


import os
import uuid

from flask import (
    Blueprint, jsonify, request
)

from project.api.models import Port
from project.api.models import Host
from project.api.models import EP
from project import db
from project.api.settings import node_ips, vnis
from common.rpc import TrnRpc

ports_blueprint = Blueprint('ports', __name__)

eps = []

def ports_update_eps_config():
    eps_conf = {
        'size': len(eps),
        'eps': eps
    }
    for ip in node_ips:
        rpc = TrnRpc(ip)
        rpc.update_droplet(eps_conf)
        del rpc
    eps.clear()

@ports_blueprint.route('/ports', methods=['GET', 'POST'])
def all_ports():
    if request.method == 'POST':
        portList = request.get_json()
        for post_data in portList:
            port = Port(
                port_id = post_data.get('port_id'),
                mac_port = post_data.get('mac_port'),
                vpc_id = post_data.get('vpc_id'))

            host = Host.query.filter_by(ip_node=post_data.get('ip_node')).first()
            if host is None:
                host = Host(
                    mac_node = post_data.get('mac_node'),
                    ip_node = post_data.get('ip_node'))
                host.host_id=str(uuid.uuid4())
                db.session.add(host)
            port.host_id = host.host_id

            for ip in post_data['ips_port']:
                ep = EP(**ip)
                ep.port_id = post_data['port_id']
                port.eps.append(ep)

            db.session.add(port)
            db.session.commit()
            ep = {
                "vni": vnis.get(post_data.get('vpc_id')),
                "ip": post_data['ips_port'][0]['ip'],
                "hip": post_data.get('ip_node'),
                "mac": post_data.get('mac_port'),
                "hmac": post_data.get('mac_node')
            }
            eps.append(ep)
        response_object = portList
        ports_update_eps_config()
    else:
        response_object = [port.to_json() for port in Port.query.all()]
    return jsonify(response_object)


@ports_blueprint.route('/ports/ping', methods=['GET'])
def ping_ports():
    return jsonify({
        'status': 'success',
        'message': 'pong!',
        'container_id': os.uname()[1]
    })


@ports_blueprint.route('/ports/<port_id>', methods=['GET', 'PUT', 'DELETE'])
def single_port(port_id):
    port = Port.query.filter_by(port_id=port_id).first()
    if request.method == 'GET':
        response_object = port.to_json()
    elif request.method == 'PUT':
        post_data = request.get_json()
        port.mac_port = post_data.get('mac_port')
        db.session.commit()
        response_object = port.to_json()
    elif request.method == 'DELETE':
        db.session.delete(port)
        db.session.commit()
        response_object = {}
    return jsonify(response_object)


if __name__ == '__main__':
    app.run()
