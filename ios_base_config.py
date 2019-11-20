#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2018 Bernhard Ehlers
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
Base interface and loopback configuration for Cisco router
"""

import os
import sys
import ipaddress
import re
import telnetlib
import uuid
import xml.etree.ElementTree as ET
import gns3api


def die(*msg_list):
    """ abort program with error message """
    error_msg = ' '.join(str(x) for x in msg_list)
    sys.exit(error_msg.rstrip("\n\r"))


def next_ip_address(ip_intf):
    """" next IP address """
    return ipaddress.ip_interface(str(ip_intf.ip + 1) +
                                  "/" + str(ip_intf.network.prefixlen))


def next_ip_network(ip_intf):
    """" next IP network """
    return ipaddress.ip_interface(
        str(ip_intf.ip + ip_intf.network.num_addresses) +
        "/" + str(ip_intf.network.prefixlen))


def send_cisco_commands(name, host, port, commands, privileged=True):
    """ send config to Cisco router/switch """

    if not commands:
        return True

    prompt = b"[>#] ?$"
    status = "???"
    try:

        # open telnet connection
        status = "connect"
        tn = telnetlib.Telnet(host, port, 10)

        # read old junk
        while tn.read_until(b"xyzzy", timeout=0.3):
            pass

        # send a <CR>
        status = "first contact"
        tn.write(b"\r")
        try:
            response = tn.expect([prompt], 5)[2]
        except OSError:
            pass
        tn.write(b"\r")		# second <return>
        response = tn.expect([prompt], 5)[2]
        if privileged and response.endswith(b">"):
            sys.stderr.write("{}: Router must be in priviledged mode.\n".format(name))
            return False

        # commands
        status = "sending commands"
        for line in commands:
            while tn.read_until(b"xyzzy", timeout=0.1):
                pass
            tn.write((line + "\r").encode('utf-8', errors='replace'))
            # wait for prompt
            tn.expect([prompt])

        # close connection
        status = "close"
        tn.close()

    except OSError as err:
        sys.stderr.write("{}: I/O error during {} - {}\n".format(name, status, err))
        return False
    except KeyboardInterrupt:
        sys.stderr.write("{}: Aborted\n".format(name))
        return False

    return True			# No error


def get_project_data(project_id, sel_items):
    """ get node (with link information) and notes of a project by GNS3 API """

    # connect to GNS3 controller
    try:
        api = gns3api.GNS3Api()
    except gns3api.GNS3ApiException as err:
        die("Can't connect to GNS3 controller:", err)

    # get all node and link information
    all_nodes = {}
    all_links = {}
    notes = []
    try:
        # check project status
        project = api.request('GET', ('/v2/projects', project_id))
        if project['status'] != 'opened':
            die("Project '{}' is {}, please open it.".format(
                project['name'], project['status']))

        compute_host = {}
        for compute in api.request('GET', '/v2/computes'):
            compute_host[compute["compute_id"]] = compute["host"]
        for node in api.request('GET', ('/v2/projects', project_id, 'nodes')):
            console_host = node.get("console_host")
            if console_host in ('0.0.0.0', '::'):
                node["console_host"] = compute_host[node["compute_id"]]
            all_nodes[node["node_id"]] = node
        for link in api.request('GET', ('/v2/projects', project_id, 'links')):
            all_links[link["link_id"]] = link

        if sel_items:			# get selected notes
            for item in sel_items:
                if item.startswith("text_drawings/"):
                    drawing = api.request('GET', \
                        ('/v2/projects', project_id, "drawings", item[14:]))
                    svg = ET.fromstring(drawing["svg"])
                    if svg[0].tag == 'text':
                        notes.append(svg[0].text)
        else:				# nothing selected: get all of them
            for drawing in api.request('GET', ('/v2/projects', project_id, "drawings")):
                svg = ET.fromstring(drawing["svg"])
                if svg[0].tag == 'text':
                    notes.append(svg[0].text)

    except gns3api.GNS3ApiException as err:
        die("Can't get node/link information:", err)

    nodes = select_nodes(all_nodes, all_links, sel_items)

    return nodes, notes


def select_nodes(all_nodes, all_links, sel_items):
    """ select nodes and add link information """
    nodes = {}
    try:
        if sel_items:			# get selected nodes
            for item in sel_items:
                if item.startswith("nodes/"):
                    item = item[6:]
                    nodes[all_nodes[item]['name']] = all_nodes[item]
                    nodes[all_nodes[item]['name']]['_links'] = []
        else:				# nothing selected: get all nodes
            for item in all_nodes:
                nodes[all_nodes[item]['name']] = all_nodes[item]
                nodes[all_nodes[item]['name']]['_links'] = []

        # add link informations to nodes
        for link in all_links:
            link_nodes = all_links[link]['nodes']
            node_0_id = link_nodes[0]['node_id']
            node_1_id = link_nodes[1]['node_id']
            node_0_name = all_nodes[node_0_id]['name']
            node_1_name = all_nodes[node_1_id]['name']
            label_0 = link_nodes[0].get("label", {}).get("text")
            label_1 = link_nodes[1].get("label", {}).get("text")
            if node_0_name in nodes:
                nodes[node_0_name]['_links'].append(
                    {'link_id': link, 'link_type': all_links[link]['link_type'],
                     'adapter_number': link_nodes[0].get('adapter_number'),
                     'port_number': link_nodes[0].get('port_number'),
                     'label': label_0,
                     'remote_name': node_1_name, 'remote_label': label_1})
            if node_1_name in nodes:
                nodes[node_1_name]['_links'].append(
                    {'link_id': link, 'link_type': all_links[link]['link_type'],
                     'adapter_number': link_nodes[1].get('adapter_number'),
                     'port_number': link_nodes[1].get('port_number'),
                     'label': label_1,
                     'remote_name': node_0_name, 'remote_label': label_0})
    except KeyError:
        die("Project informations are inconsistent")

    return nodes


def get_vlan_interfaces(nodes):
    """ get vlan interfaces in switch groups """
    vlan_interfaces = {}
    for name in nodes:
        is_switch = False
        switch_group = {}		# new switch group
        switch_list = [name]
        while switch_list:		# process a group of switches
            name = switch_list.pop()
            if name not in nodes:	# node not selected
                continue
            if name in vlan_interfaces:	# already processed
                continue
            for link in nodes[name]['_links']:
                if not link['label']:
                    pass
                elif re.search(r'\btrunk\b', link['label'], re.IGNORECASE):
                    is_switch = True
                    switch_list.append(link['remote_name'])
                else:
                    match = re.search(r'\bvlan *(\d+)\b', link['label'], re.IGNORECASE)
                    if match:		# add vlan / link to vlan_interfaces
                        is_switch = True
                        vlan = int(match.group(1))
                        switch_group.setdefault(vlan, [])
                        switch_group[vlan].append(
                            [name, link['label'],
                             link['remote_name'], link['remote_label'],
                             link['link_id']])
            if is_switch:
                vlan_interfaces[name] = switch_group
        for vlan in switch_group:
            switch_group[vlan].sort(key=lambda k: [k[0].lower(), k[1].lower()])
    for name in vlan_interfaces:
        nodes[name]['_vlans'] = sorted(vlan_interfaces[name].keys())

    return vlan_interfaces


def base_networks(notes):
    """ get base IP networks for loopbacks and infrastructure interfaces """

    loopback_base = None
    infra_base = None

    for note in notes:
        # loopback address
        match = re.search(r'^ *loopback: *(\S+)', note,
                          flags=re.IGNORECASE|re.MULTILINE)
        if match:
            if loopback_base is None:
                try:
                    loopback_base = ipaddress.ip_interface(match.group(1))
                except ValueError:
                    die("Invalid loopback address '{}'".format(match.group(1)))
            else:
                die("Multiple loopback addresses")

        # infrastructure address
        match = re.search(r'^ *infralink: *(\S+)', note,
                          flags=re.IGNORECASE|re.MULTILINE)
        if match:
            if infra_base is None:
                try:
                    infra_base = ipaddress.ip_interface(match.group(1))
                except ValueError:
                    die("Invalid infrastructure link address '{}'".format(match.group(1)))
                if infra_base.network.num_addresses < 4:
                    die("Network '{}' is too small for 2 interface addresses.".format(infra_base.with_prefixlen))
                if infra_base.ip == infra_base.network.network_address:
                    infra_base = next_ip_address(infra_base)
                if infra_base.ip + 1 >= infra_base.network.broadcast_address:
                    die("'{}' or it's next address is the broadcast address.".format(infra_base.with_prefixlen))
            else:
                die("Multiple infrastructure link addresses")

    if loopback_base is None:
        die("No loopback address defined")
    if infra_base is None:
        die("No infrastructure link (InfraLink) address defined")

    return loopback_base, infra_base


def cisco_router_config(notes):
    """ get additional cisco router config """

    router_config = []

    for note in notes:
        match = re.search(r'\bcisco +router +config *:', note,
                          flags=re.IGNORECASE)
        if match:
            conf_pos = match.end()
            router_config.extend(note[conf_pos:].strip().splitlines())

    return router_config


def sorted_node_names(nodes):
    """ return sorted list of node names """
    return sorted(nodes, key=lambda k: str(k).lower())


def sorted_links(links):
    """ return sorted list of node links """
    return sorted(links, key=lambda k: "" if k['label'] is None else \
                                       str(k['label']).lower())


def add_link_ip(nodes, vlan_interfaces, ip_net_base):
    """" Add IP addresses to the links between the nodes """

    for name in sorted_node_names(nodes):
        if '_vlans' in nodes[name]:
            continue
        for link in sorted_links(nodes[name]['_links']):
            if not link['label'] or not link['remote_label']:
                continue
            if 'IP' in link:
                continue
            if link['remote_name'] in vlan_interfaces:
                match = re.search(r'\bvlan *(\d+)\b', link['remote_label'], re.IGNORECASE)
                if match:		# link to switch group
                    vlan = int(match.group(1))
                    ip_addr = ip_net_base
                    ip_count = 0
                    ip_last_link = None
                    for switch_if in vlan_interfaces[link['remote_name']][vlan]:
                        rem_name = switch_if[2]
                        rem_link_id = switch_if[4]
                        if rem_name not in vlan_interfaces:
                            if rem_name in nodes:
                                for rem_link in nodes[rem_name]['_links']:
                                    if rem_link['link_id'] == rem_link_id:
                                        rem_link['IP'] = ip_addr
                                        ip_count += 1
                                        ip_last_link = rem_link
                                        break
                            ip_addr = next_ip_address(ip_addr)
                    if ip_count == 1:		# ignore networks with 1 IP
                        del ip_last_link['IP']
                    elif ip_count >= 2:
                        ip_net_base = next_ip_network(ip_net_base)
            elif link['remote_name'] in nodes:
                for rem_link in nodes[link['remote_name']]['_links']:
                    if rem_link['link_id'] == link['link_id']:
                        if 'IP' not in rem_link:
                            link['IP'] = ip_net_base
                            rem_link['IP'] = next_ip_address(ip_net_base)
                            ip_net_base = next_ip_network(ip_net_base)
                        break
    return ip_net_base


def add_loopback(nodes, ip_net_base):
    """" Add loopback to nodes """

    for name in sorted_node_names(nodes):
        if '_vlans' in nodes[name]:
            continue
        nodes[name].setdefault("_loopback", {})
        if 0 not in nodes[name]['_loopback']:
            nodes[name]['_loopback'][0] = ip_net_base
            ip_net_base = next_ip_network(ip_net_base)
    return ip_net_base


def str_clean(arg):
    """ cleanup string: collapse whitespaces """
    return " ".join(str(arg).split())


class CiscoRouter(dict):
    """ cisco router """

    def create_config(self):
        """ create router configuration """

        config = []
        if self['node_type'] == 'qemu':
            config.append("hostname {}".format(self['name']))

        for loopback in sorted(self.get('_loopback', [])):
            ip, mask = self['_loopback'][loopback].with_netmask.split('/', 1)
            config.append("interface lo{}".format(loopback))
            config.append(" ip address {} {}".format(ip, mask))

        for link in sorted_links(self['_links']):
            if not link['label']:
                continue
            config.append("interface {}".format(link['label']))
            config.append(" description {} {}".format(
                link['remote_name'], str_clean(link['remote_label'])))
            if 'IP' in link:
                ip, mask = link['IP'].with_netmask.split('/', 1)
                config.append(" ip address {} {}".format(ip, mask))
                config.append(" no shutdown")

        config += self.get('_router_config', [])
        if config:
            config = ["configure terminal"] + config + ["end"]

        return config

    def send_commands(self, commands):
        """ send commands to router """
        return send_cisco_commands(self['name'], self["console_host"],
                                   self["console"], commands)

class CiscoSwitch(dict):
    """ cisco switch """

    def create_config(self):
        """ create switch configuration """

        config = []
        vlan_database = []

        if self['node_type'] == 'qemu':
            config.append("hostname {}".format(self['name']))

        if self['node_type'] == 'dynamips':
            for vlan in self.get('_vlans', []):
                vlan_database.append("vlan {}".format(vlan))
            if vlan_database:
                vlan_database = ["vlan database"] + vlan_database + ["exit"]
        else:
            for vlan in self.get('_vlans', []):
                config.append("vlan {}".format(vlan))

        for link in sorted_links(self['_links']):
            if not link['label']:
                continue
            match = re.match(r'([a-zA-Z]+ ?)?[0-9.:/]*[0-9]', link['label'])
            if not match:
                continue
            ifname = match.group(0)
            config.append("interface {}".format(ifname))
            config.append(" description {} {}".format(
                link['remote_name'], str_clean(link['remote_label'])))
            if re.search(r'\btrunk\b', link['label'], re.IGNORECASE):
                config.append(" switchport trunk encapsulation dot1q")
                config.append(" switchport mode trunk")
            else:
                match = re.search(r'\bvlan *(\d+)\b', link['label'], re.IGNORECASE)
                if match:		# access link
                    vlan = int(match.group(1))
                    config.append(" switchport access vlan {}".format(vlan))
                    config.append(" switchport mode access")

        if config:
            config = ["configure terminal"] + config + ["end"]
        config = vlan_database + config

        return config

    def send_commands(self, commands):
        """ send commands to switch """
        return send_cisco_commands(self['name'], self["console_host"],
                                   self["console"], commands)


def select_cisco_devices(nodes, notes):
    """ select cisco devices, using some heuristics """

    devices = {}
    router_config = cisco_router_config(notes)
    print("Checking for devices, that are non Cisco router/switches...")
    for name in sorted_node_names(nodes):
        node = nodes[name]
        if node["node_type"] == 'dynamips':
            properties = node.get("properties", {})
            if "NM-16ESW" in (properties.get("slot0"), properties.get("slot1"),
                              properties.get("slot2"), properties.get("slot3"),
                              properties.get("slot4"), properties.get("slot5"),
                              properties.get("slot6")):
                devices[name] = CiscoSwitch(node)
            else:
                devices[name] = CiscoRouter(node)
                if router_config:
                    devices[name]['_router_config'] = router_config
        elif node["node_type"] == 'iou':
            properties = node.get("properties", {})
            image = properties.get("path", "").lower()
            image = image.split("/")[-1]
            if "l2" in image:
                devices[name] = CiscoSwitch(node)
            elif "l3" in image:
                devices[name] = CiscoRouter(node)
                if router_config:
                    devices[name]['_router_config'] = router_config
            else:
                print("  {}: unknown IOU device type".format(node["name"]))
        elif node["node_type"] == 'qemu':
            properties = node.get("properties", {})
            image = properties.get("hda_disk_image", "")
            image = image.replace("\\", "/").split("/")[-1].lower()
            if "ios" in image:
                if "l2" in image:
                    devices[name] = CiscoSwitch(node)
                else:
                    devices[name] = CiscoRouter(node)
                    if router_config:
                        devices[name]['_router_config'] = router_config
            else:
                print("  {}: is not an IOS node".format(node["name"]))
        else:
            print("  {}: Non Cisco type '{}'".format(node["name"], node["node_type"]))

    return devices


def get_project_id(argv):
    """ parse command line args and determine the project ID """

    if len(argv) <= 1 or argv[1] == '-h' or argv[1] == '-?':
        prog_name = os.path.splitext(os.path.basename(argv[0]))[0]
        die("Usage: {} <project>".format(prog_name))

    project_id = None
    sel_items = []

    if len(argv) == 2:			# started as a script
        try:				# check, if argument is project UUID
            uuid.UUID(argv[1])
            project_id = argv[1]
        except ValueError:		# argument is project name
            # connect to GNS3 controller
            try:
                api = gns3api.GNS3Api()
            except gns3api.GNS3ApiException as err:
                die("Can't connect to GNS3 controller:", err)

            # search for the project id
            project_name = argv[1]
            for proj in api.request('GET', '/v2/projects'):
                if proj['name'] == project_name:
                    project_id = proj['project_id']
                    break
            else:
                die("Project '{}' not found".format(project_name))

    elif len(argv) >= 3:		# started as an external tool
        project_id = argv[2]
        sel_items = argv[3:]

    return project_id, sel_items


def main(argv):
    """ Main function """

    project_id, sel_items = get_project_id(argv)

    # get nodes (with link informations) and notes by GNS3 API
    nodes, notes = get_project_data(project_id, sel_items)
    if not nodes:
        die("No nodes selected")
    vlan_interfaces = get_vlan_interfaces(nodes)

    # get base networks from notes
    loopback_base, infra_base = base_networks(notes)

    # select the Cisco devices
    devices = select_cisco_devices(nodes, notes)
    if not devices:
        die("No Cisco routers/switches found")

    # assign links and IP addresses
    add_loopback(devices, loopback_base)
    add_link_ip(devices, vlan_interfaces, infra_base)

    # configure devices
    print("Configuring...")
    for name in sorted_node_names(devices):
        node = devices[name]
        if node["status"] != "started":
            sys.stderr.write("{}: Node status is '{}'\n".format(name, node["status"]))
        elif node.get("console") is None or \
             node.get("console_host") is None or \
             node.get("console_type") != "telnet":
            sys.stderr.write("{}: Doesn't use telnet console\n".format(name))
        else:
            config = node.create_config()
            if config:
                print("{}...".format(name))
                node.send_commands(config)
            else:
                print("{}: Nothing to configure.".format(name))


if __name__ == "__main__":
    main(sys.argv)
