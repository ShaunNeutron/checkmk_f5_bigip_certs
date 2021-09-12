#!/usr/env python
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# License: GNU General Public License v3

## Custom check for F5 certificate expiration. 
## Author: Shaun Pillé
## Contact: shaun.pille@gmail.com
## Version 0.3
## Modification: Andreas Doehler
## Version 0.4 - Rewrite for CMK 2.0+
## Modification: Shaun Pillé

import time
from datetime import datetime
from .agent_based_api.v1 import *
from cmk.base.plugins.agent_based.agent_based_api.v1.type_defs import (
    DiscoveryResult,
    CheckResult,
    StringTable,
)

# Parse function
def parse_f5_bigip_certs(string_table):
    parsed = {}
    ignore_list = set(
        [   
            "/Common/default.crt",
            "/Common/f5-irule.crt",
            "/Common/ca-bundle.crt",
            "/Common/f5-ca-bundle.crt",
            "/Common/f5_api_com.crt",
        ]
    )
    for certname, epochdate in string_table:
        if certname not in ignore_list:
            certname=certname[8:] 	#remove /Common/ from cert names
            parsed[certname]=epochdate
    return parsed
    
#SNMP Data
register.snmp_section(
        name='f5_bigip_certs',
        detect=matches ('.1.3.6.1.4.1.3375.2.1.4.1.0', 'BIG-IP'),
        parse_function=parse_f5_bigip_certs,
        fetch=SNMPTree(
                base='.1.3.6.1.4.1.3375.2.1.15.1.2.1',
                oids=[
                        '1',    #certname
                        '5',    #certexpire in epoch
        ]),
)

# Discover function
def discover_f5_bigip_certs(section) -> DiscoveryResult:
    for certname in section:
        yield Service(item=certname)

# Check function
def check_f5_bigip_certs(item, params, section) -> CheckResult:
    now = time.time()
    state=''
    epochdate = int(section[item])
    timediff = epochdate - now

    if epochdate < now:
        message = "EXPIRED %s days ago" % int(timediff/86400)
        result = State.CRIT
    elif timediff < params['crit']:
        message = "%s days remain. Cert expires on %s" % (int(timediff/86400), datetime.fromtimestamp(epochdate),)
        result = State.CRIT
    elif timediff < params['warn']:
        message = "%s days remain. Cert expires on %s" % (int(timediff/86400), datetime.fromtimestamp(epochdate),)
        result = State.WARN
    else:
        message = "%s days remain. Cert expires on %s" % (int(timediff/86400), datetime.fromtimestamp(epochdate),)
        result = State.OK

    yield Result(state=result, notice=message)

# checkdata to pull matching SNMP strings
register.check_plugin(
        name='f5_bigip_certs',
        service_name='Cert Expiration for %s',
        discovery_function=discover_f5_bigip_certs,
        check_function=check_f5_bigip_certs,
        check_default_parameters={
            'warn': 2592000,
            'crit': 864000,
        },
        check_ruleset_name='f5_bigip_certs',
)
