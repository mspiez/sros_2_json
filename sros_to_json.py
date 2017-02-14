import os
import re
import json
import copy
from netaddr import *


class Slicing(object):
    def __init__(self, config):
        self.config = config
        self.customer_sec = None
        self.sdp_sec = None
        self.svc_sec = None
        self.hostname = None
        self.sys_ip = None
        self.sap_list = None
        self.sdp_using_list = None

    def sap_list_return(self):
        self.sap_list = re.findall('\s+sap (\S+)', self.config) 
        return self.sap_list

    def sdp_using_return(self):
        self.sdp_using_list = re.findall('-sdp (\S+)', self.config) 
        return self.sdp_using_list

    def hostname_return(self):
        try:
            self.hostname = re.search('    system\n        name "(.*)"', self.config).group(1)
        except Exception:
            self.hostname = None
        return self.hostname

    def sys_ip_return(self):
        try:
            self.sys_ip = re.search('interface "system"\n            address (\d+\.\d+\.\d+\.\d+)/\d+', self.config).group(1)
        except Exception:
            self.sys_ip = None
        return self.sys_ip

    def _svc_sect_slice(self):
        self.customer_sec = None
        self.sdp_sec = None
        self.svc_sec = None
        try:
            section_start = self.config.index('echo "Service Configuration"')
        except Exception:
            section_start = 'Not Found'
        section_end = '\n    exit'
        if section_start != 'Not Found':
            ser_section = self.config[section_start:]
            try:
                service_section = ser_section[:ser_section.index(section_end)]
            except Exception:
                service_section = 'Not Found'
            try:
                svc_check = re.search('        \w+ \d+ customer', service_section).group(0)
            except Exception:
                svc_check = False
            try:
                cust_check = re.search('        customer \d+ create', service_section).group(0)
            except Exception:
                cust_check = False
            try:
                sdp_check = re.search('        sdp \d+ ', service_section).group(0)
            except Exception:
                sdp_check = False
            if service_section != 'Not Found':
                try:
                    section_recon = re.search('\n    service\n        (\S+)', service_section).group(1)
                except Exception:
                    section_recon = None
                if 'sdp' in section_recon:
                    if sdp_check:
                        self.sdp_sec_start = service_section.index(sdp_check)
                        if cust_check:
                            self.sdp_sec_end = service_section.index(cust_check)
                            self.sdp_sec = service_section[self.sdp_sec_start:self.sdp_sec_end]
                        elif svc_check:
                            self.sdp_sec_end = service_section.index(svc_check)
                            self.sdp_sec = service_section[self.sdp_sec_start:self.sdp_sec_end]
                        else:
                            self.sdp_sec = service_section[self.sdp_sec_start:]
                    else:
                        self.sdp_sec = 'Not Found'
                    if cust_check:
                        self.customer_sec_start = service_section.index(cust_check)
                        if svc_check:
                            self.customer_sec_end = service_section.index(svc_check)
                            self.customer_sec = service_section[self.customer_sec_start:self.customer_sec_end]
                        else:
                            self.customer_sec = service_section[self.customer_sec_start:]
                    else:
                        self.customer_sec = 'Not Found'       
                    if svc_check:
                        self.svc_sec_start = service_section.index(svc_check)
                        self.svc_sec = service_section[self.svc_sec_start:]
                    else:
                        self.svc_sec = 'Not Found'
                elif 'customer' in section_recon:
                    if cust_check:
                        self.customer_sec_start = service_section.index(cust_check)
                        if sdp_check:
                            self.customer_sec_end = service_section.index(sdp_check)
                            self.customer_sec = service_section[self.customer_sec_start:self.customer_sec_end]
                        elif svc_check:
                            self.customer_sec_end = service_section.index(svc_check)
                            self.customer_sec = service_section[self.customer_sec_start:self.customer_sec_end]
                        else:
                            self.customer_sec = service_section[self.customer_sec_start:]
                    else:
                        self.customer_sec = 'Not Found'       
                    if sdp_check:
                        self.sdp_sec_start = service_section.index(sdp_check)
                        if svc_check:
                            self.sdp_sec_end = service_section.index(svc_check)
                            self.sdp_sec = service_section[self.sdp_sec_start:self.sdp_sec_end]
                        else:
                            self.sdp_sec = service_section[self.sdp_sec_start:]
                    else:
                        self.sdp_sec = 'Not Found'       
                    if svc_check:
                        self.svc_sec_start = service_section.index(svc_check)
                        self.svc_sec = service_section[self.svc_sec_start:]
                    else:
                        self.svc_sec = 'Not Found'
                else:
                    if svc_check:
                        self.svc_sec_start = service_section.index(svc_check)
                        self.svc_sec = service_section[self.svc_sec_start:]
                    else:
                        self.svc_sec = 'Not Found'
                return {self.config:{
                                'customer_section': self.customer_sec,
                                'sdp_section': self.sdp_sec,
                                'service_section': self.svc_sec,
                                'hostname': self.hostname
                                }}

    def customer_list(self):
        try:
            customers = self.customer_sec.split('\n        exit')
        except Exception:
            customers = None    
        if customers != None:
            cust_list = []
            for customer in customers:
                if 'customer' in customer:
                    try:
                        customer_id = re.search('customer (\d+) create', customer).group(1)
                    except Exception:
                        customer_id = 'Not Found'
                    try:
                        customer_desc = re.search('description "(.*)"', customer).group(1)
                    except Exception:
                        customer_desc = 'Not Found'
                    cust_list.append({
                                    'customer_id': customer_id,
                                    'customer_desc': customer_desc
                                    })
            return cust_list

    def sdp_list(self):
        try:
            sdp_s = self.sdp_sec.split('\n        exit')
        except Exception:
            sdp_s = None
        if sdp_s != None:
            sdp_list = []
            for sdp in sdp_s:
                if 'sdp' in sdp:
                    sdp_id = re.search('sdp (\d+)', sdp)
                    try:
                        sdp_id = sdp_id.group(1)
                    except Exception:
                        sdp_id = None
                    if 'mpls create' in sdp:
                        sdp_type = 'MPLS'
                    else:
                        sdp_type = 'GRE'
                    try:
                        far_end = re.search('far-end (\d+.\d+.\d+.\d+)', sdp).group(1)
                    except Exception:
                        far_end = None
                    try:
                        desc = desc = re.search('description "(.*)"', sdp).group(1)
                    except Exception:
                        desc = None
                    try:
                        path_mtu = path_mtu = re.search('path-mtu (\d+)', sdp).group(1)
                    except Exception:
                        path_mtu = None
                    if 'ldp' in sdp:
                        ldp = 'Yes'
                    else:
                        ldp = None
                    try:
                        lsp = lsp = re.search('            lsp "(.*)"', sdp).group(1)
                    except Exception:
                        lsp = None
                    if 'bgp' in sdp:
                        bgp_enabled = 'Yes'
                    else:
                        bgp_enabled = None
                    pw_ports = re.findall('                (pw-port \d+ vc-id \d+) create', sdp)
                    sdp_list.append({
                                    'Sdp_hostname': self.hostname,
                                    'Sdp_sys_ip': self.sys_ip,
                                    'Sdp_id': sdp_id,
                                    'Sdp_type': sdp_type,
                                    'Far_end': far_end,
                                    'Description': desc,
                                    'Path_mtu': path_mtu,
                                    'Ldp': ldp,
                                    'Lsp': lsp,
                                    'Bgp_enabled': bgp_enabled,
                                    'Pw_ports': pw_ports
                                    })
            return sdp_list

    def _service_split(self):
        try:
            service_list = self.svc_sec.split('\n        exit')
        except Exception:
            service_list = None
        return service_list

    def vprn_parms(self, service_list):
        vprns_parameters = []
        if service_list != None:
            for svc in service_list:
                svc_id = re.search('vprn (\d+) customer \d+', svc)
                cust_id = re.search('vprn \d+ customer (\d+)', svc)
                svc_desc = re.search('description "(.*)"', svc)
                svc_name = re.search('service-name "(.*)"', svc)
                vrf_import = re.search('vrf-import "(.*)"', svc)
                vrf_export = re.search('vrf-export "(.*)"', svc)
                auto_sys = re.search('autonomous-system (\d+)', svc)
                rd = re.search('route-distinguisher (\S+:\S+)', svc)
                auto_bind = re.search('auto-bind (.*)', svc)
                vrf_target = re.search('vrf-target (target:\d+:\d+)', svc)
                interfaces = re.findall('\n            interface "(.*)"', svc)
                static_routes = re.findall('            (static-route \d+\.\d+\.\d+\.\d+/\d+ next-hop \d+\.\d+\.\d+\.\d+)', svc)
                try:
                    svc_id = svc_id.group(1)
                except Exception:
                    svc_id = None
                try:
                    cust_id = cust_id.group(1)
                except Exception:
                    cust_id = None
                try:
                    svc_desc = svc_desc.group(1)
                except Exception:
                    svc_desc = None
                try:
                    svc_name = svc_name.group(1)
                except Exception:
                    svc_name = None
                try:
                    vrf_import = vrf_import.group(1)
                except Exception:
                    vrf_import = None
                try:
                    vrf_export = vrf_export.group(1)
                except Exception:
                    vrf_export = None
                try:
                    auto_sys = auto_sys.group(1)
                except Exception:
                    auto_sys = None
                try:
                    rd = rd.group(1)
                except Exception:
                    rd = None
                try:
                    auto_bind = auto_bind.group(1)
                except Exception:
                    auto_bind = None
                try:
                    vrf_target = vrf_target.group(1)
                except Exception:
                    vrf_target = None
                if svc_id != None:
                    iface_parms = self.vprn_ifaces(svc)
                    bgp_groups = self._vprn_bgp_groups(svc)
                    one_vprn_parms = {
                                    'Hostname': self.hostname,
                                    'System_ip': self.sys_ip,
                                    'Service_type': 'Vprn',
                                    'Service_id': svc_id,
                                    'Cust_id': cust_id,
                                    'Svc_desc': svc_desc,
                                    'Svc_name': svc_name,
                                    'Vrf_import': vrf_import,
                                    'Vrf_export': vrf_export,
                                    'Autonomous_sys': auto_sys,
                                    'RD': rd,
                                    'Auto_bind': auto_bind,
                                    'Vrf_target': vrf_target,
                                    'All_interfaces': interfaces,
                                    'Static_routes': static_routes,
                                    'Interfaces': iface_parms,
                                    'BGP_groups': bgp_groups
                                    }
                    vprns_parameters.append(one_vprn_parms)
            return vprns_parameters

    def vprn_ifaces(self, single_service):
        vprn_ifaces = None
        svc_id = re.search('vprn (\d+) customer \d+', single_service)
        if svc_id:
            iface_start = re.search('\n            (interface)', single_service)
            rd = re.search('route-distinguisher (\S+:\S+)', single_service)
            if rd and iface_start:
                try:
                    interface_section = single_service[single_service.index(iface_start.group(1)):]
                except Exception:
                    interface_section = None
                if interface_section != None:
                    vprn_interfaces = interface_section.split('\n            exit')
                    vprn_ifaces = self.vprn_iface_parms(vprn_interfaces)
        return vprn_ifaces

    def vprn_iface_parms(self, interface_list):
        vprn_interfaces = []
        for interface in interface_list:
            iface_name = re.search('interface "(.*)" create', interface)
            iface_description = re.search('\n                description "(.*)"', interface)
            iface_address = re.search('\n                address (\d+.\d+.\d+.\d+/\d+)', interface)
            iface_sec_address = re.findall('                secondary (\d+.\d+.\d+.\d+/\d+)', interface)
            spoke_sdp = re.search('\n                spoke-sdp (\d+:\d+)', interface)
            ip_mtu = re.search('\n                ip-mtu (\d+)', interface)
            try:
                sap = re.search('sap (\S+) create', interface).group(1)
            except Exception:
                sap = None
            if sap != None:
                if ':' in sap:
                    sap_vlan = sap.split(':')[1]
                    sap_port = sap.split(':')[0]
                elif ':' not in sap:
                    sap_vlan = 'null'
                    sap_port = sap
                sec_start = interface.index(sap)
                sap_sec = interface[sec_start:]
                sap_end = re.search('\n                exit', sap_sec)
                if sap_end:
                    sap_sec_end = sap_sec.index(sap_end.group(0))
                    sap_section = sap_sec[:sap_sec_end]
                else:
                    sap_section = sap_sec
            else:
                sap_section = None
            if sap_section != None:
                try:
                    sap_desc = re.search('description "(.*)"', sap_section).group(1)
                except Exception:
                    sap_desc = None
                try:
                    ingress = re.search('ingress', sap_section).group(0)
                except Exception:
                    ingress = None
                try:
                    egress = re.search('egress', sap_section).group(0)
                except Exception:
                    egress = None
                if ingress:
                    ingress_start = sap_section.index(ingress)
                    ingress_sec = sap_section[ingress_start:].split('\n                    exit')[0]
                else:
                    ingress_sec = None
                if egress:
                    egress_start = sap_section.index(egress)
                    egress_sec = sap_section[egress_start:]
                else:
                    egress_sec = None
                try:
                    ingress_qos = re.search('qos (\d+)', ingress_sec).group(1)
                except Exception:
                    ingress_qos = None
                try:
                    ingress_sched = re.search('scheduler-policy "(.*)"', ingress_sec).group(1)
                except Exception:
                    ingress_sched = None
                try:
                    ingress_filter = re.search('filter (.*)', ingress_sec).group(1)
                except Exception:
                    ingress_filter = None
                try:
                    egress_qos = re.search('qos (\d+)', egress_sec).group(1)
                except Exception:
                    egress_qos = None
                try:
                    egress_sched = re.search('scheduler-policy "(.*)"', egress_sec).group(1)
                except Exception:
                    egress_sched = None
                try:
                    egress_filter = re.search('filter (.*)', egress_sec).group(1)
                except Exception:
                    egress_filter = None
            else:
                sap_desc = None
                ingress_qos = None
                ingress_sched = None
                ingress_filter = None
                egress_qos = None
                egress_sched = None
                egress_filter = None
                sap_vlan = None
                sap_port = None
                sap_id = None
            try:
                iface_name = iface_name.group(1)
            except Exception:
                iface_name = None
            try:
                iface_description = iface_description.group(1)
            except Exception:
                iface_description = None
            try:
                iface_address = iface_address.group(1)
            except Exception:
                iface_address = None
            if not iface_sec_address:
                iface_sec_address = None
            try:
                spoke_sdp = spoke_sdp.group(1)
            except Exception:
                spoke_sdp = None
            try:
                ip_mtu = ip_mtu.group(1)
            except Exception:
                ip_mtu = None
            if iface_name != None:
                vprn_interfaces.append({
                                'Name': iface_name,
                                'Iface_desc': iface_description,
                                'Iface_address': iface_address,
                                'Iface_sec_address': iface_sec_address,
                                'Spoke_sdp': spoke_sdp,
                                'IP_mtu': ip_mtu,
                                'Sap_id': sap,
                                'Sap_desc': sap_desc,
                                'Sap_port': sap_port,
                                'Sap_vlan': sap_vlan,
                                'Sap_ingress_qos': ingress_qos,
                                'Sap_ingress_scheduler': ingress_sched,
                                'Sap_ingress_filter': ingress_filter,                               
                                'Sap_egress_qos': egress_qos,
                                'Sap_egress_scheduler': egress_sched,
                                'Sap_egress_filter': egress_filter,
                                'Static_routes': []
                })
        return vprn_interfaces

    def _vprn_statics(self, vprn_parms):
        if vprn_parms['Interfaces'] != None and vprn_parms['Static_routes'] != []:
            static_routes = vprn_parms['Static_routes']
            for interface in vprn_parms['Interfaces']:
                if interface['Iface_sec_address'] == None and interface['Iface_address'] != None:
                    int_network = IPNetwork(interface['Iface_address'])
                    for static in static_routes:
                        try:
                            next_hop = re.search('next-hop (\d+\.\d+\.\d+\.\d+)', static).group(1)
                        except Exception:
                            next_hop = None
                        if next_hop != None:
                            if IPAddress(next_hop) in int_network:
                                interface['Static_routes'].append(static)
                elif interface['Iface_sec_address'] != None:
                    addresses = copy.deepcopy(interface['Iface_sec_address'])
                    addresses.append(interface['Iface_address'])
                    for address in addresses:
                        int_network = IPNetwork(address)
                        for static in static_routes:
                            try:
                                next_hop = re.search('next-hop (\d+\.\d+\.\d+\.\d+)', static).group(1)
                            except Exception:
                                next_hop = None
                            if next_hop != None:
                                if IPAddress(next_hop) in int_network:
                                    interface['Static_routes'].append(static)

    def _vprn_bgp_groups(self, single_service):
        bgp_present = re.search('            bgp', single_service)
        if bgp_present:
            bgp_start = re.search('\n            (bgp)', single_service)
            rd = re.search('route-distinguisher (\d+:\d+)', single_service)
            if rd and bgp_start:
                try:
                    bgp_section = single_service[single_service.index(bgp_start.group(1)):]
                except Exception:
                    bgp_section = None
                if bgp_section != None:
                    bgp_groups = bgp_section.split('\n                exit')
                    bgp_groups_list = []
                    for bgp_group in bgp_groups:
                        if 'group' in bgp_group:
                            try:
                                bgp_group_name = re.search('\n                group "(.*)"', bgp_group).group(1)
                            except:
                                bgp_group_name = None
                            try:
                                export_policy = re.search('\n                    export "(.*)"', bgp_group).group(1)
                            except Exception:
                                export_policy = None
                            try:
                                import_policy = re.search('\n                    import "(.*)"', bgp_group).group(1)
                            except Exception:
                                import_policy = None
                            bgp_neighbors = bgp_group.split('\n                    exit')
                            bgp_neighbors_list = []
                            for bgp_neighbor in bgp_neighbors:
                                try:
                                    neighbor = re.search('\n                    neighbor (\d+.\d+.\d+.\d+)', bgp_neighbor).group(1)
                                except Exception:
                                    neighbor = None
                                try:
                                    peer_as = re.search('\n                        peer-as (\d+)', bgp_neighbor).group(1)
                                except Exception:
                                    peer_as = None
                                if neighbor != None:
                                    bgp_neighbors_list.append({
                                                        'Neighbor': neighbor,
                                                        'Peer_as': peer_as
                                                            })
                            bgp_groups_list.append({
                                                    'Group_name': bgp_group_name,
                                                    'Export_policy': export_policy,
                                                    'Import_policy': import_policy,
                                                    'BGP_neighbors': bgp_neighbors_list
                                                        })
            else:
                bgp_groups_list = None
        else:
            bgp_groups_list = None
        return bgp_groups_list

    def epipe_parms(self, service_list):
        epipe_parameters = []
        if service_list != None:
            for svc in service_list:
                try:
                    service_id = re.search('epipe (\d+) customer \d+', svc).group(1)
                except Exception:
                    service_id = None
                if service_id != None:
                    try:
                        cust_id = re.search('epipe \d+ customer (\d+)', svc).group(1)
                    except Exception:
                        cust_id = None
                    service = re.search('epipe (\d+) customer (\d+)( vc-switching)? create', svc)
                    try:
                        vc_switch = service.group(3)
                    except Exception:
                        vc_switch = None
                    try:
                        svc_desc = re.search('description "(.*)"', svc).group(1)
                    except Exception:
                        svc_desc = None
                    try:   
                        svc_name = re.search('service-name "(.*)"', svc).group(1)
                    except Exception:
                        svc_name = None
                    try:
                        svc_mtu = re.search('service-mtu (\d+)', svc).group(1)
                    except Exception:
                        svc_mtu = None
                    try:   
                        mtu_check = re.search('(no service-mtu-check)\n', svc).group(0)
                    except Exception:
                        mtu_check = None
                    sap_list = re.findall('(sap \S+)', svc)
                    spoke_list = re.findall('spoke-sdp (\S+:\d+)', svc)
                    endpoints = re.findall('endpoint "(.*)"', svc)
                    sap_parms = []
                    sdp_parms = []
                    if sap_list != []:   
                        for sap in sap_list:
                            sap_sec = svc[svc.find('{}'.format(sap)):]
                            sap_sec = sap_sec[:sap_sec.find('            exit')]
                            try:
                                sap = re.search('sap (\S+)', sap_sec).group(1)
                            except Exception:
                                sap = None
                            if sap != None:
                                if ':' in sap:
                                    sap_vlan = sap.split(':')[1]
                                    sap_port = sap.split(':')[0]
                                elif ':' not in sap:
                                    sap_vlan = 'null'
                                    sap_port = sap
                            try:
                                sap_description = re.search('description "(.*)"', sap_sec).group(1)
                            except Exception:
                                sap_description = None
                            qos_ingress_sec = sap_sec[sap_sec.find('ingress\n'):]
                            qos_ingress_sec = qos_ingress_sec[:qos_ingress_sec.find('                exit\n')]
                            try:
                                ingress_qos = re.search('qos (\d+)', qos_ingress_sec).group(1)
                            except Exception:
                                ingress_qos = None
                            try:
                                ingress_scheduler = re.search('scheduler-policy "(.*)"', qos_ingress_sec).group(1)
                            except Exception:
                                ingress_scheduler = None
                            try:
                                sap_endpoint = re.search('sap \S+ endpoint (.*)').group(1)
                            except Exception:
                                sap_endpoint = None
                            qos_egress_sec = sap_sec[sap_sec.find('egress\n'):]
                            qos_egress_sec = qos_ingress_sec[:qos_egress_sec.find('                exit\n')]
                            try:
                                egress_qos = re.search('qos (\d+)', qos_egress_sec).group(1)
                            except Exception:
                                egress_qos = None
                            try:
                                egress_scheduler = re.search('scheduler-policy "(.*)"', qos_egress_sec).group(1)
                            except Exception:
                                egress_scheduler = None
                            #print sap_id.group(1), vlan_id.group(1), ingress_qos, ingress_scheduler, egress_qos, egress_scheduler, sap_id, vlan_id
                            sap_parms.append({
                                            'Sap_id': sap,
                                            'Sap_port': sap_port,
                                            'Sap_vlan': sap_vlan,
                                            'Sap_desc': sap_description,
                                            'Ingress_qos': ingress_qos,
                                            'Ingress_scheduler': ingress_scheduler,
                                            'Sap_endpoint': sap_endpoint,
                                            'Egress_qos': egress_qos,
                                            'Egress_scheduler': egress_scheduler
                                            })
                    else:
                        sap_parms = None
   
                    if spoke_list != []:
                        for sdp in spoke_list:
                            spoke_id = sdp.split(':')[0]
                            vc_id = sdp.split(':')[1]
                            try:
                                sdp_endpoint = re.search('spoke-sdp \d+:\d+ endpoint "(.*)"', svc).group(1)
                            except Exception:
                                sdp_endpoint = None
                            try:
                                icb = re.search('(icb) create', svc).group(1)
                            except Exception:
                                icb = None
                            sdp_sec = svc[svc.find('{}'.format(sdp)):]
                            sdp_sec = sdp_sec[:sdp_sec.find('            exit')]
                            try:
                                sdp_description = re.search('description "(.*)"', sdp_sec).group(1)
                            except Exception:
                                sdp_description = None
                            try:
                                precedence = re.search('precedence (.*)', sdp_sec).group(1)
                            except Exception:
                                precedence = None
                            #print spoke_id, vc_id, sdp_endpoint, icb, sasdp_description, precedence
                            sdp_parms.append({
                                            'Sdp_id': spoke_id,
                                            'Vc_id': vc_id,
                                            'Sdp_endpoint': sdp_endpoint,
                                            'Sdp_desc': sdp_description,
                                            'Precedence': precedence,
                                            'Sdp_type': 'spoke'
                                            })
                    else:
                        sdp_parms = None
                    epipe_parameters.append({
                                        'Hostname': self.hostname,
                                        'System_ip': self.sys_ip,
                                        'Service_type': 'Epipe',
                                        'Service_id': service_id,
                                        'Cust_id': cust_id,
                                        'Vc_switch': vc_switch,
                                        'Svc_desc': svc_desc,
                                        'Svc_name': svc_name,
                                        'Svc_mtu': svc_mtu,
                                        'Mtu_check': mtu_check,
                                        'Sap_parms': sap_parms,
                                        'Sdp_parms': sdp_parms
                                        })   
            return epipe_parameters

    def ies_parms(self, service_list):
        ies_ifaces_list = []
        if service_list != None:
            for svc in service_list:
                try:
                    service_id = re.search('ies (\d+) customer \d+', svc).group(1)
                except Exception:
                    service_id = None
                if service_id != None:
                    try:
                        cust_id = re.search('ies \d+ customer (\d+)', svc).group(1)
                    except Exception:
                        cust_id = None
                    try:
                        svc_name = re.search('\n            service-name "(.*)"', svc).group(1)
                    except Exception:
                        svc_name = None
                    try:
                        svc_desc = re.search('\n            description "(.*)"', svc).group(1)
                    except Exception:
                        svc_desc = None
                    try:
                        iface_start = re.search('\n            (interface)', svc).group(1)
                    except Exception:
                        iface_start = None
                    if iface_start != None:
                        interface_section = svc[svc.find(iface_start):]
                        ies_ifaces = interface_section.split('\n            exit')
                        if ies_ifaces != []:
                            ies_ifaces_parms = self.vprn_iface_parms(ies_ifaces)
                        else:
                            ies_ifaces_parms = None
                        ies_ifaces_list.append({
                                        'Hostname': self.hostname,
                                        'System_ip': self.sys_ip,
                                        'Service_type': 'Ies',
                                        'Service_id': service_id,
                                        'Cust_id': cust_id,
                                        'Svc_name': svc_name,
                                        'Svc_desc': svc_desc,
                                        'Interfaces': ies_ifaces_parms,
                                        'Static_routes': []
                                        })
            return ies_ifaces_list

    def _ies_statics(self, ies_parms):
        ies_static_routes = re.findall('\n        (static-route \d+.\d+.\d+.\d+/\d+ next-hop.*)', self.config)
        if ies_static_routes != []:
            for interface in ies_parms['Interfaces']:
                if interface['Iface_sec_address'] == None and interface['Iface_address'] != None:
                    int_network = IPNetwork(interface['Iface_address'])
                    for static in ies_static_routes:
                        try:
                            next_hop = re.search('next-hop (\d+\.\d+\.\d+\.\d+)', static).group(1)
                        except Exception:
                            next_hop = None
                        if next_hop != None:
                            if IPAddress(next_hop) in int_network:
                                interface['Static_routes'].append(static)
                elif interface['Iface_sec_address'] != None:
                    addresses = copy.deepcopy(interface['Iface_sec_address'])
                    addresses.append(interface['Iface_address'])
                    for address in addresses:
                        int_network = IPNetwork(address)
                        for static in ies_static_routes:
                            try:
                                next_hop = re.search('next-hop (\d+\.\d+\.\d+\.\d+)', static).group(1)
                            except Exception:
                                next_hop = None
                            if next_hop != None:
                                if IPAddress(next_hop) in int_network:
                                    interface['Static_routes'].append(static)

    def bgp_global(self):
        try:
            bgp_start = self.config.index('echo "BGP Configuration"')
        except Exception:
            bgp_start = 'Not Found'
        bgp_end = '\n    exit'
        if bgp_start != 'Not Found':
            bgp_section = self.config[bgp_start:]
            try:
                bgp_sec = bgp_section[:bgp_section.index(bgp_end)]
            except Exception:
                bgp_sec = 'Not Found'
            if bgp_sec != 'Not Found':
                try:
                    vpn_apply_import = re.search('\n            (vpn-apply-import)', bgp_sec).group(1)
                except Exception:
                    vpn_apply_import = None
                try:
                    vpn_apply_export = re.search('\n            (vpn-apply-export)', bgp_sec).group(1)
                except Exception:
                    vpn_apply_export = None
                try:
                    igp_shortcut = re.search('\n            igp-shortcut (.*)', bgp_sec).group(1)
                except Exception:
                    igp_shortcut = None
                try:
                    global_local_as = re.search('\n            local-as (\d+)', bgp_sec).group(1)
                except Exception:
                    global_local_as = None
                try:
                    bgp_router_id = re.search('\n            router-id (.*)', bgp_sec).group(1)
                except Exception:
                    bgp_router_id = None
                try:
                    transport_tunnel = re.search('\n            transport-tunnel (.*)', bgp_sec).group(1)
                except Exception:
                    transport_tunnel = None
                try:
                    back_up_path = re.search('\n            backup-path (.*)', bgp_sec).group(1)
                except Exception:
                    back_up_path = None
                bgp_groups = bgp_sec.split('\n            exit')
                bgp_groups_list = []
                for bgp_group in bgp_groups:
                        if 'group' in bgp_group:
                            try:
                                bgp_group_name = re.search('\n            group "(.*)"', bgp_group).group(1)
                            except Exception:
                                bgp_group_name = None
                            try:
                                export_policy = re.search('\n                export "(.*)"', bgp_group).group(1)
                            except Exception:
                                export_policy = None
                            try:
                                import_policy = re.search('\n                import "(.*)"', bgp_group).group(1)
                            except Exception:
                                import_policy = None
                            try:
                                bgp_family = re.search('\n                family (.*)', bgp_group).group(1)
                            except Exception:
                                bgp_family = None
                            try:
                                bgp_nex_hop_self = re.search('\n                (next-hop-self)', bgp_group).group(1)
                            except Exception:
                                bgp_nex_hop_self = None
                            try:
                                group_type = re.search('\n                type (.*)', bgp_group).group(1)
                            except Exception:
                                group_type = None
                            try:
                                group_peer_as = re.search('\n                peer-as (\d+)', bgp_group).group(1)
                            except Exception:
                                group_peer_as = None
                            bgp_neighbors = bgp_group.split('\n                exit')
                            bgp_neighbors_list = []
                            for bgp_neighbor in bgp_neighbors:
                                try:
                                    neighbor = re.search('\n                neighbor (\d+.\d+.\d+.\d+)', bgp_neighbor).group(1)
                                except Exception:
                                    neighbor = None
                                try:
                                    peer_as = re.search('\n                    peer-as (\d+)', bgp_neighbor).group(1)
                                except Exception:
                                    peer_as = None
                                try:
                                    neighbor_export = re.search('\n                    export "(.*)"', bgp_neighbor).group(1)
                                except Exception:
                                    neighbor_export = None
                                if neighbor != None:
                                    bgp_neighbors_list.append({
                                                        'Neighbor': neighbor,
                                                        'Neighbor_Peer_as': peer_as,
                                                        'Neighbor_export': neighbor_export
                                                            })
                            bgp_groups_list.append({
                                                    'Group_name': bgp_group_name,
                                                    'Export_policy': export_policy,
                                                    'Import_policy': import_policy,
                                                    'Bgp_family': bgp_family,
                                                    'Bgp_nex_hop_self': bgp_nex_hop_self,
                                                    'Group_type': group_type,
                                                    'Group_peer_as': group_peer_as,
                                                    'BGP_neighbors': bgp_neighbors_list
                                                        })
                return bgp_groups_list

    def port_list(self):
        try:
            port_start = self.config.index('echo "Port Configuration"')
        except Exception:
            port_start = 'Not Found'
        port_boarder = '\n#--------------------------------------------------'
        if port_start != 'Not Found':
            port_section = self.config[port_start:]
            try:
                port_section = port_section.split(port_boarder)[1]
            except Exception:
                port_section = None
            if port_section != 'None':
                ports = port_section.split('\n    exit')
                port_parms = []
                for port_sec in ports:
                    try:
                        port_id = re.search('\n    port (\S+)', port_sec).group(1)
                    except Exception:
                        port_id = None
                    try:
                        port_type = re.search('\n        (ethernet)', port_sec).group(1)
                    except Exception:
                        port_type = None
                    try:
                        port_mode = re.search('\n            mode (.*)', port_sec).group(1)
                    except Exception:
                        port_mode = None
                    try:
                        port_encap = re.search('\n            encap-type (.*)', port_sec).group(1)
                    except Exception:
                        port_encap = None
                    try:
                        port_desc = re.search('\n        description "(.*)"', port_sec).group(1)
                    except Exception:
                        port_desc = None
                    try:
                        port_shutdown = re.search('\n        (shutdown)', port_sec).group(1)
                    except Exception:
                        port_shutdown = None
                    if port_id != None:
                        port_parms.append({
                                        'Hostname': self.hostname,
                                        'System_ip': self.sys_ip,
                                        'Port_id': port_id,
                                        'Port_type': port_type,
                                        'Port_mode': port_mode,
                                        'Port_encap': port_encap,
                                        'Port_desc': port_desc,
                                        'Port_shutdown': port_shutdown,
                                        'Sap_s': []
                                        })
                return port_parms

    def lag_list(self):
        try:
            lag_start = self.config.index('echo "LAG Configuration"')
        except Exception:
            lag_start = 'Not Found'
        lag_boarder = '\n#--------------------------------------------------'
        if lag_start != 'Not Found':
            lag_section = self.config[lag_start:]
            try:
                lag_section = lag_section.split(lag_boarder)[1]
            except Exception:
                lag_section = None
            if lag_section != 'None':
                lags = lag_section.split('\n    exit')
                lag_parms = []
                for lag_sec in lags:
                    try:
                        lag_id = re.search('\n    lag (\S+)', lag_sec).group(1)
                    except Exception:
                        lag_id = None
                    lag_ports = re.findall('\n        port (\S+)', lag_sec)
                    try:
                        lag_lacp = re.search('\n        lacp (.*)', lag_sec).group(1)
                    except Exception:
                        lag_lacp = None
                    try:
                        lag_mode = re.search('\n        mode (.*)', lag_sec).group(1)
                    except Exception:
                        lag_mode = None
                    try:
                        lag_encap = re.search('\n        encap-type (.*)', lag_sec).group(1)
                    except Exception:
                        lag_encap = None
                    try:
                        lag_desc = re.search('\n        description "(.*)"', lag_sec).group(1)
                    except Exception:
                        lag_desc = None
                    try:
                        lag_shutdown = re.search('\n        (shutdown)', lag_sec).group(1)
                    except Exception:
                        lag_shutdown = None
                    if lag_id != None:
                        lag_parms.append({
                                    'Hostname': self.hostname,
                                    'System_ip': self.sys_ip,
                                    'Lag_id': lag_id,
                                    'Lag_ports': lag_ports,
                                    'Lag_lacp': lag_lacp,
                                    'Lag_mode': lag_mode,
                                    'Lag_encap': lag_encap,
                                    'Lag_desc': lag_desc,
                                    'Lag_shutdown': lag_shutdown,
                                    'Sap_s': []
                                        })
                return lag_parms

    def vpls_parms(self, service_list):
        vpls_parameters = []
        if service_list != None:
            for svc in service_list:
                try:
                    service_id = re.search('vpls (\d+) customer \d+', svc).group(1)
                except Exception:
                    service_id = None
                if service_id != None:
                    try:
                        cust_id = re.search('vpls \d+ customer (\d+)', svc).group(1)
                    except Exception:
                        cust_id = None
                    service = re.search('vpls (\d+) customer (\d+)( etree)? create', svc)
                    try:
                        etree = service.group(3)
                    except Exception:
                        etree = None
                    try:
                        svc_desc = re.search('description "(.*)"', svc).group(1)
                    except Exception:
                        svc_desc = None
                    try:   
                        svc_name = re.search('service-name "(.*)"', svc).group(1)
                    except Exception:
                        svc_name = None
                    try:
                        svc_mtu = re.search('service-mtu (\d+)', svc).group(1)
                    except Exception:
                        svc_mtu = None
                    try:   
                        mtu_check = re.search('(no service-mtu-check)\n', svc).group(0)
                    except Exception:
                        mtu_check = None
                    try:
                        svc_shutdown = re.search('            (shutdown)', svc).group(1)
                    except Exception:
                        svc_shutdown = None
                    sap_list = re.findall('(sap \S+)', svc)
                    sdp_list = re.findall('(\S+-sdp \S+:\S+)', svc)
                    endpoints = re.findall('endpoint "(.*)"', svc)
                    split_horizon_groups = re.findall('\n            split-horizon-group "(.*)"', svc)
                    sap_parms = []
                    sdp_parms = []
                    if sap_list != []:
                        for sap in sap_list:
                            sap_sec = svc[svc.find('{}'.format(sap)):]
                            sap_sec = sap_sec[:sap_sec.find('            exit')]
                            try:
                                sap = re.search('sap (\S+)', sap_sec).group(1)
                            except Exception:
                                sap = None
                            if sap != None:
                                if ':' in sap:
                                    sap_vlan = sap.split(':')[1]
                                    sap_port = sap.split(':')[0]
                                elif ':' not in sap:
                                    sap_vlan = 'null'
                                    sap_port = sap
                                try:
                                    icb = re.search('(icb) create', sap_sec).group(1)
                                except Exception:
                                    icb = None
                                try:
                                    split_horizon_group = re.search('split-horizon-group "(.*)" create', sap_sec).group(1)
                                except Exception:
                                    split_horizon_group = None
                                try:
                                    sap_description = re.search('description "(.*)"', sap_sec).group(1)
                                except Exception:
                                    sap_description = None
                                qos_ingress_sec = sap_sec[sap_sec.find('ingress\n'):]
                                qos_ingress_sec = qos_ingress_sec[:qos_ingress_sec.find('                exit\n')]
                                try:
                                    ingress_qos = re.search('qos (\d+)', qos_ingress_sec).group(1)
                                except Exception:
                                    ingress_qos = None
                                try:
                                    ingress_scheduler = re.search('scheduler-policy "(.*)"', qos_ingress_sec).group(1)
                                except Exception:
                                    ingress_scheduler = None
                                try:
                                    sap_endpoint = re.search('sap \S+ endpoint "(.*)"').group(1)
                                except Exception:
                                    sap_endpoint = None
                                qos_egress_sec = sap_sec[sap_sec.find('egress\n'):]
                                qos_egress_sec = qos_ingress_sec[:qos_egress_sec.find('                exit\n')]
                                try:
                                    egress_qos = re.search('qos (\d+)', qos_egress_sec).group(1)
                                except Exception:
                                    egress_qos = None
                                try:
                                    egress_scheduler = re.search('scheduler-policy "(.*)"', qos_egress_sec).group(1)
                                except Exception:
                                    egress_scheduler = None
                                try:
                                    sap_shutdown = re.search('                (shutdown)', sap_sec).group(1)
                                except Exception:
                                    sap_shutdown = None
                                #print sap_id.group(1), vlan_id.group(1), ingress_qos, ingress_scheduler, egress_qos, egress_scheduler, sap_id, vlan_id
                                sap_parms.append({
                                                'Sap_id': sap,
                                                'Sap_port': sap_port,
                                                'Sap_vlan': sap_vlan,
                                                'Icb': icb,
                                                'Split_horizon_group': split_horizon_group,
                                                'Sap_desc': sap_description,
                                                'Ingress_qos': ingress_qos,
                                                'Ingress_scheduler': ingress_scheduler,
                                                'Sap_endpoint': sap_endpoint,
                                                'Egress_qos': egress_qos,
                                                'Egress_scheduler': egress_scheduler,
                                                'Shutdown': sap_shutdown
                                                })
                    if sdp_list != []:
                        for sdp in sdp_list:
                            sdp_id = sdp.split(':')[0].split(' ')[1]
                            vc_id = sdp.split(':')[1]
                            sdp_sec = svc[svc.find('{}'.format(sdp)):]
                            sdp_sec = sdp_sec[:sdp_sec.find('            exit')]
                            try:
                                sdp_type = re.search('(\S+)-sdp \d+:\d+', sdp_sec).group(1)
                            except Exception:
                                sdp_type = None
                            try:
                                sdp_vc_type = re.search('-sdp \d+:\d+ vc-type (\S+)', sdp_sec).group(1)
                            except Exception:
                                sdp_vc_type = None
                            try:
                                sdp_endpoint = re.search('-sdp \d+:\d+ endpoint "(.*)"', sdp_sec).group(1)
                            except Exception:
                                sdp_endpoint = None
                            try:
                                split_horizon_group = re.search('split-horizon-group "(.*)" create', sdp_sec).group(1)
                            except Exception:
                                split_horizon_group = None
                            try:
                                root_leaf_tag = re.search('(root-leaf-tag) create', sdp_sec).group(1)
                            except Exception:
                                root_leaf_tag = None
                            try:
                                icb = re.search('(icb) create', sdp_sec).group(1)
                            except Exception:
                                icb = None
                            try:
                                sdp_description = re.search('description "(.*)"', sdp_sec).group(1)
                            except Exception:
                                sdp_description = None
                            try:
                                precedence = re.search('precedence (.*)', sdp_sec).group(1)
                            except Exception:
                                precedence = None
                            try:
                                sdp_shutdown = re.search('                (shutdown)', sdp_sec).group(1)
                            except Exception:
                                sdp_shutdown = None
                            sdp_parms.append({
                                            'Sdp_id': sdp_id,
                                            'Vc_id': vc_id,
                                            'Sdp_type': sdp_type,
                                            'Sdp_vc_type': sdp_vc_type,
                                            'Split_horizon_group': split_horizon_group,
                                            'Root_leaf_tag': root_leaf_tag,
                                            'Icb': icb,
                                            'Sdp_endpoint': sdp_endpoint,
                                            'Sdp_desc': sdp_description,
                                            'Precedence': precedence,
                                            'Shutdown': sdp_shutdown
                                            })
                    vpls_parameters.append({
                                        'Hostname': self.hostname,
                                        'System_ip': self.sys_ip,
                                        'Service_type': 'Vpls',
                                        'Service_id': service_id,
                                        'Cust_id': cust_id,
                                        'Etree': etree,
                                        'Svc_desc': svc_desc,
                                        'Svc_name': svc_name,
                                        'Svc_mtu': svc_mtu,
                                        'Mtu_check': mtu_check,
                                        'Endpoints': endpoints,
                                        'Split_horizon_groups': split_horizon_groups,
                                        'Sap_parms': sap_parms,
                                        'Sdp_parms': sdp_parms,
                                        'Shutdown': svc_shutdown
                                        })
            return vpls_parameters

    def sap_parms_list(self, service_list):
        list_of_sap_parms = []
        for service in service_list:
            if service['Service_type'] == 'Vprn':
                try:
                    ifaces = service['Interfaces']
                except Exception:
                    ifaces = None
                if ifaces != None:
                    if service['Interfaces'] != []:
                        for iface in service['Interfaces']:
                            try:
                                cust_name = service['Cust_name']
                            except Exception:
                                cust_name = None
                            list_of_sap_parms.append({
                                                'Sap_id': iface['Sap_id'],
                                                'Sap_vlan': iface['Sap_vlan'],
                                                'Sap_port': iface['Sap_port'],
                                                'Sap_service_id': service['Service_id'],
                                                'Sap_service_type': service['Service_type'],
                                                'Sap_desc': iface['Sap_desc'],
                                                'Sap_customer_id': service['Cust_id'],
                                                'Sap_customer_name': cust_name,
                                                'Sap_hostname': self.hostname,
                                                'Sap_sys_ip': self.sys_ip
                                                })
            if service['Service_type'] == 'Epipe':
                try:
                    saps = service['Sap_parms']
                except Exception:
                    saps = None
                if saps != None:
                    if service['Sap_parms'] != []:
                        for sap in service['Sap_parms']:
                            try:
                                cust_name = service['Cust_name']
                            except Exception:
                                cust_name = None
                            list_of_sap_parms.append({
                                                'Sap_id': sap['Sap_id'],
                                                'Sap_vlan': sap['Sap_vlan'],
                                                'Sap_port': sap['Sap_port'],
                                                'Sap_service_id': service['Service_id'],
                                                'Sap_service_type': service['Service_type'],
                                                'Sap_desc': sap['Sap_desc'],
                                                'Sap_customer_id': service['Cust_id'],
                                                'Sap_customer_name': cust_name,
                                                'Sap_hostname': self.hostname,
                                                'Sap_sys_ip': self.sys_ip
                                                })            
            if service['Service_type'] == 'Ies':
                try:
                    ifaces = service['Interfaces']
                except Exception:
                    ifaces = None
                if ifaces != None:
                    if service['Interfaces'] != []:
                        for iface in service['Interfaces']:
                            try:
                                cust_name = service['Cust_name']
                            except Exception:
                                cust_name = None
                            list_of_sap_parms.append({
                                                'Sap_id': iface['Sap_id'],
                                                'Sap_vlan': iface['Sap_vlan'],
                                                'Sap_port': iface['Sap_port'],
                                                'Sap_service_id': service['Service_id'],
                                                'Sap_service_type': service['Service_type'],
                                                'Sap_desc': iface['Sap_desc'],
                                                'Sap_customer_id': service['Cust_id'],
                                                'Sap_customer_name': cust_name,
                                                'Sap_hostname': self.hostname,
                                                'Sap_sys_ip': self.sys_ip
                                                })
            if service['Service_type'] == 'Vpls':
                try:
                    saps = service['Sap_parms']
                except Exception:
                    saps = None
                if saps != None:
                    if service['Sap_parms'] != []:
                        for sap in service['Sap_parms']:
                            try:
                                cust_name = service['Cust_name']
                            except Exception:
                                cust_name = None
                            list_of_sap_parms.append({
                                                'Sap_id': sap['Sap_id'],
                                                'Sap_vlan': sap['Sap_vlan'],
                                                'Sap_port': sap['Sap_port'],
                                                'Sap_service_id': service['Service_id'],
                                                'Sap_service_type': service['Service_type'],
                                                'Sap_desc': sap['Sap_desc'],
                                                'Sap_customer_id': service['Cust_id'],
                                                'Sap_customer_name': cust_name,
                                                'Sap_hostname': self.hostname,
                                                'Sap_sys_ip': self.sys_ip
                                                })
        return list_of_sap_parms   

    def iface_parms_list(self, vprn_list, ies_list):
        list_of_iface_parms = []
        if vprn_list != None:
            for vprn in vprn_list:
                try:
                    ifaces = vprn['Interfaces']
                except Exception:
                    ifaces = None
                if ifaces != None:
                    if vprn['Interfaces'] != []:
                        for iface in vprn['Interfaces']:
                            list_of_iface_parms.append({
                                                'Iface_name': iface['Name'],
                                                'Iface_address': iface['Iface_address'],
                                                'Iface_sec_address': iface['Iface_sec_address'],
                                                'Iface_sap_id': iface['Sap_id'],
                                                'Iface_sap_vlan': iface['Sap_vlan'],
                                                'Iface_sap_port': iface['Sap_port'],
                                                'Iface_service_id': vprn['Service_id'],
                                                'Iface_service_type': 'vprn',
                                                'Iface_desc': iface['Iface_desc'],
                                                'Iface_customer': vprn['Cust_id'],
                                                'Iface_hostname': self.hostname,
                                                'Iface_sys_ip': self.sys_ip,
                                                'IP_mtu': iface['IP_mtu'],
                                                'Iface_sdp': iface['Spoke_sdp'],
                                                'Iface_static_route': iface['Static_routes']
                                                })
        if ies_list != None:
            for ies in ies_list:
                try:
                    ifaces = ies['Interfaces']
                except Exception:
                    ifaces = None
                if ifaces != None:
                    if ies['Interfaces'] != []:
                        for iface in ies['Interfaces']:
                            list_of_iface_parms.append({
                                                'Iface_name': iface['Name'],
                                                'Iface_address': iface['Iface_address'],
                                                'Iface_sec_address': iface['Iface_sec_address'],
                                                'Iface_sap_id': iface['Sap_id'],
                                                'Iface_sap_vlan': iface['Sap_vlan'],
                                                'Iface_sap_port': iface['Sap_port'],
                                                'Iface_service_id': ies['Service_id'],
                                                'Iface_service_type': 'ies',
                                                'Iface_desc': iface['Iface_desc'],
                                                'Iface_customer': ies['Cust_id'],
                                                'Iface_hostname': self.hostname,
                                                'Iface_sys_ip': self.sys_ip,
                                                'IP_mtu': iface['IP_mtu'],
                                                'Iface_sdp': iface['Spoke_sdp'],
                                                'Iface_static_route': iface['Static_routes']
                                                })
        return list_of_iface_parms

    def sdp_parms(self, sap, epipe_list, vpls_list, sdp_list):
        #Method finds local SDP parms based on sap_parms_list() method
        sdp_s_list = []
        try:
            sap_type = sap['Sap_service_type']
        except Exception:
            sap_type = None
        if sap_type != None:
            if sap_type == 'Epipe' and epipe_list != None:
                for epipe in epipe_list:
                    if epipe['Service_id'] == sap['Sap_service_id']:
                        try:
                            sdp_s = epipe['Sdp_parms']
                        except Exception:
                            sdp_s = None
                        if sdp_s != None:
                            for spoke in epipe['Sdp_parms']:
                                epipe_svc_id = epipe['Service_id']
                                spoke_vc_id = spoke['Vc_id']
                                spoke_id = spoke['Sdp_id']
                                for sdp in sdp_list:
                                    if sdp['Sdp_id'] == spoke_id:
                                        far_end_sys_ip = sdp['Far_end']
                                        sdp_s_list.append({
                                                'Sdp_hostname': self.hostname,
                                                'Sdp_sys_ip': self.sys_ip,
                                                'Service_id': epipe_svc_id,
                                                'Sdp_vc_id': spoke_vc_id,
                                                'Sdp_id': spoke_id,
                                                'Far_end_sys_ip': far_end_sys_ip,
                                                'Service_type': 'Epipe',
                                                'Sdp_type': 'spoke'
                                                    })
            elif sap_type == 'Vpls' and vpls_list != None:
                for vpls in vpls_list:
                    if vpls['Service_id'] == sap['Sap_service_id']:
                        try:
                            sdp_s = vpls['Sdp_parms']
                        except Exception:
                            sdp_s = None
                        if sdp_s != None:
                            for spoke in vpls['Sdp_parms']:
                                vpls_svc_id = vpls['Service_id']
                                spoke_vc_id = spoke['Vc_id']
                                spoke_id = spoke['Sdp_id']
                                for sdp in sdp_list:
                                    if sdp['Sdp_id'] == spoke_id:
                                        far_end_sys_ip = sdp['Far_end']
                                        sdp_s_list.append({
                                                'Sdp_hostname': self.hostname,
                                                'Sdp_sys_ip': self.sys_ip,
                                                'Service_id': vpls_svc_id,
                                                'Sdp_vc_id': spoke_vc_id,
                                                'Sdp_id': spoke_id,
                                                'Far_end_sys_ip': far_end_sys_ip,
                                                'Service_type': 'Vpls',
                                                'Sdp_type': spoke['Sdp_type']
                                                    })                           
            return sdp_s_list

    def sdp_using_parms(self, service_list, sdp_list):
        #Method finds all SDPs parms for a given config based on generated list from Slicing Class
        sdp_s_list = []
        if service_list != None:
            for service in service_list:
                if service['Service_type'] == 'Epipe':
                    try:
                        sdp_s = service['Sdp_parms']
                    except Exception:
                        sdp_s = None
                    if sdp_s != None:
                        for spoke in service['Sdp_parms']:
                            epipe_svc_id = service['Service_id']
                            spoke_vc_id = spoke['Vc_id']
                            spoke_id = spoke['Sdp_id']
                            for sdp in sdp_list:
                                if sdp['Sdp_id'] == spoke_id:
                                    far_end_sys_ip = sdp['Far_end']
                                    sdp_s_list.append({
                                            'Service_id': epipe_svc_id,
                                            'Vc_id': spoke_vc_id,
                                            'Sdp_id': spoke_id,
                                            'Far_end_sys_ip': far_end_sys_ip,
                                            'Service_type': 'Epipe',
                                            'Sdp_hostname': self.hostname,
                                            'Sdp_sys_ip': self.sys_ip,
                                            'Sdp_type': 'spoke'
                                                })
                if service['Service_type'] == 'Vpls':
                    try:
                        sdp_s = service['Sdp_parms']
                    except Exception:
                        sdp_s = None
                    if sdp_s != None:
                        for spoke in service['Sdp_parms']:
                            vpls_svc_id = service['Service_id']
                            spoke_vc_id = spoke['Vc_id']
                            spoke_id = spoke['Sdp_id']
                            for sdp in sdp_list:
                                if sdp['Sdp_id'] == spoke_id:
                                    far_end_sys_ip = sdp['Far_end']
                                    sdp_s_list.append({
                                            'Service_id': vpls_svc_id,
                                            'Vc_id': spoke_vc_id,
                                            'Sdp_id': spoke_id,
                                            'Far_end_sys_ip': far_end_sys_ip,
                                            'Service_type': 'Vpls',
                                            'Sdp_hostname': self.hostname,
                                            'Sdp_sys_ip': self.sys_ip,
                                            'Sdp_type': spoke['Sdp_type']
                                                })
                if service['Service_type'] == 'Vprn':
                    try:
                        ifaces = service['Interfaces']
                    except Exception:
                        ifaces = None
                    if ifaces != None and ifaces != []:
                        for iface in ifaces:
                            vprn_svc_id = service['Service_id']
                            try:
                                spoke_vc_id = iface['Spoke_sdp'].split(':')[1]
                                spoke_id = iface['Spoke_sdp'].split(':')[0]
                            except Exception:
                                spoke_vc_id = None
                                spoke_id = None
                            for sdp in sdp_list:
                                if sdp['Sdp_id'] == spoke_id:
                                    far_end_sys_ip = sdp['Far_end']
                                    sdp_s_list.append({
                                                    'Service_id': vprn_svc_id,
                                                    'Vc_id': spoke_vc_id,
                                                    'Sdp_id': spoke_id,
                                                    'Far_end_sys_ip': far_end_sys_ip,
                                                    'Service_type': 'vprn',
                                                    'Sdp_hostname': self.hostname,
                                                    'Sdp_sys_ip': self.sys_ip,
                                                    'Sdp_type': 'spoke'
                                                        })
                if service['Service_type'] == 'Ies':
                    try:
                        ifaces = service['Interfaces']
                    except Exception:
                        ifaces = None
                    if ifaces != None and ifaces != []:
                        for iface in ifaces:
                            ies_svc_id = service['Service_id']
                            try:
                                spoke_vc_id = iface['Spoke_sdp'].split(':')[1]
                                spoke_id = iface['Spoke_sdp'].split(':')[0]
                            except Exception:
                                spoke_vc_id = None
                                spoke_id = None
                            for sdp in sdp_list:
                                if sdp['Sdp_id'] == spoke_id:
                                    far_end_sys_ip = sdp['Far_end']
                                    sdp_s_list.append({
                                                    'Service_id': ies_svc_id,
                                                    'Vc_id': spoke_vc_id,
                                                    'Sdp_id': spoke_id,
                                                    'Far_end_sys_ip': far_end_sys_ip,
                                                    'Service_type': 'ies',
                                                    'Sdp_hostname': self.hostname,
                                                    'Sdp_sys_ip': self.sys_ip,
                                                    'Sdp_type': 'spoke'
                                                        })
            return sdp_s_list

    def layer_2_svc_sdp_count(self, service):
        try:
            sdp_count = len(service['Sdp_parms'])
        except Exception:
            sdp_count = None
        if sdp_count != None:
            return sdp_count

    def service_list(self, vprn_list, ies_list, epipe_list, vpls_list):
        service_list = vprn_list + ies_list + epipe_list + vpls_list
        return service_list

    def cust_name_return(self, service_list, customer_list):
        if service_list != [] and customer_list != []:
            for service in service_list:
                try:
                    cust_id = service['Cust_id']
                except Exception:
                    cust_id = None
                if cust_id != None:
                    for customer in customer_list:
                        if cust_id == customer['customer_id']:
                            service_list[service_list.index(service)]['Cust_name'] = customer['customer_desc']

    def port_saps(self, port_list, sap_list):
        if sap_list != [] and port_list != []:
            for sap in sap_list:
                try:
                    sap_port = sap['Sap_port']
                except Exception:
                    sap_port = None
                if sap_port != None:
                    for port in port_list:
                        if port['Port_id'] == sap_port:
                            port['Sap_s'].append(sap)

    def lag_saps(self, lag_list, sap_list):
        if sap_list != [] and lag_list != []:
            for sap in sap_list:
                try:
                    sap_port = sap['Sap_port']
                except Exception:
                    sap_port = None
                if sap_port != None and lag_list != None:
                    for lag_port in lag_list:
                        if 'lag-' + lag_port['Lag_id'] == sap_port:
                            lag_port['Sap_s'].append(sap)
