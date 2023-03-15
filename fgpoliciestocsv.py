#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of fgpoliciestocsv.
#
# Copyright (C) 2014, 2022, Thomas Debize <tdebize at mail.com>
# All rights reserved.
#
# fgpoliciestocsv is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# fgpoliciestocsv is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with fgpoliciestocsv.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from os import path 
import io
import sys
import re
import csv
import os
import shlex

# OptionParser imports
from optparse import OptionParser
from optparse import OptionGroup

# Options definition
parser = OptionParser(usage="%prog [options]")

main_grp = OptionGroup(parser, 'Main parameters')
main_grp.add_option('-i', '--input-file', help='Partial or full Fortigate configuration file. Ex: fgfw.cfg')
main_grp.add_option('-o', '--output-file', help='Output csv file (default ./policies-out.csv)', default=path.abspath(path.join(os.getcwd(), './policies-out.csv')))
main_grp.add_option('-s', '--skip-header', help='Do not print the csv header', action='store_true', default=False)
main_grp.add_option('-n', '--newline', help='Insert a newline between each policy for better readability', action='store_true', default=False)
main_grp.add_option('-d', '--delimiter', help='CSV delimiter (default ",")', default=',')
main_grp.add_option('-e', '--input-encoding', help='Input file encoding (default "utf-8")', default='utf-8')
main_grp.add_option('-f', '--output-encoding', help='Output file encoding (default "utf-8-sig" to make it easily viewable with MS Excel)', default='utf-8-sig')
main_grp.add_option('-a', '--parse-iface-alias', help='Also parse interface alias', default=True)
parser.option_groups.extend([main_grp])

# Python 2 and 3 compatibility
if (sys.version_info < (3, 0)):
    fd_read_options = 'r'
    fd_write_options = 'wb'
else:
    fd_read_options = 'r'
    fd_write_options = 'w'

# Handful patterns
# -- Entering policy definition block
p_entering_policy_block = re.compile(r'^\s*config firewall policy$', re.IGNORECASE)
p_entering_subpolicy_block = re.compile(r'^\s*config .*$', re.IGNORECASE)

p_entering_iface_block = re.compile(r'^\s*config system interface$', re.IGNORECASE)

# -- Exiting policy definition block
p_exiting_policy_block = re.compile(r'^end$', re.IGNORECASE)
p_exiting_iface_block = re.compile(r'^end$', re.IGNORECASE)

# -- Commiting the current policy definition and going to the next one
p_policy_next = re.compile(r'^next$', re.IGNORECASE)
p_iface_next = re.compile(r'^next$', re.IGNORECASE)

# -- Policy number
p_policy_number = re.compile(r'^\s*edit\s+(?P<policy_number>\d+)', re.IGNORECASE)
p_iface_name = re.compile(r'^\s*edit\s+(?P<iface_name>.+)', re.IGNORECASE)

# -- Policy setting
p_policy_set = re.compile(r'^\s*set\s+(?P<policy_key>\S+)\s+(?P<policy_value>.*)$', re.IGNORECASE)
p_iface_set = re.compile(r'^\s*set\s+(?P<iface_key>\S+)\s+(?P<iface_value>.*)$', re.IGNORECASE)

def parse_iface_alias(options):
    """
        Parse the data according to several regexes
        
        @param options:  options
        @rtype: return a list of policies ( [ {'id' : '1', 'srcintf' : 'internal', ...}, {'id' : '2', 'srcintf' : 'external', ...}, ... ] )  
                and the list of unique seen keys ['id', 'srcintf', 'dstintf', ...]
    """
    global p_entering_iface_block, p_exiting_iface_block, p_iface_next, p_iface_number, p_iface_set
    iface_alias={}
    iface_elem={}
    iface_name=""

    with io.open(options.input_file, mode=fd_read_options, encoding=options.input_encoding) as fd_input:
        for line in fd_input:
            line = line.strip()
            
            # We match a policy block
            if p_entering_iface_block.search(line):
                in_iface_block = True
    
            # We are in a policy block
            if in_iface_block:
                if p_iface_name.search(line):
                    iface_name = p_iface_name.search(line).group('iface_name')
                    print (iface_name+"\n")
                    iface_elem[u'iface_name'] = iface_name
                    iface_alias[iface_name]=iface_name
               
                # We match a setting
                if p_iface_set.search(line):
                    iface_key = p_iface_set.search(line).group('iface_key')
                    iface_value = p_policy_set.search(line).group('policy_value').strip()
                    
                    if iface_key == 'alias':
                        iface_alias[iface_name] = re.sub(r'[^\x00-\x7f]',r'', iface_value)
                
                # We are done with the current policy id
                if p_iface_next.search(line):                    
                    iface_elem = {}
                    
            
            # We are exiting the policy block
            if p_exiting_iface_block.search(line):
                in_iface_block = False
    
    return (iface_alias)


# Functions
def parse(options, iface_alias):
    """
        Parse the data according to several regexes
        
        @param options:  options
        @rtype: return a list of policies ( [ {'id' : '1', 'srcintf' : 'internal', ...}, {'id' : '2', 'srcintf' : 'external', ...}, ... ] )  
                and the list of unique seen keys ['id', 'srcintf', 'dstintf', ...]
    """
    global p_entering_policy_block, p_exiting_policy_block, p_policy_next, p_policy_number, p_policy_set
    
    in_policy_block = False
    skip_ssl_vpn_policy_block = False
    inspect_next_ssl_vpn_command = False
    
    policy_list = []
    policy_elem = {}
    
    order_keys = []
    
    with io.open(options.input_file, mode=fd_read_options, encoding=options.input_encoding) as fd_input:
        for line in fd_input:
            line = line.strip()
            
            # We match a policy block
            if p_entering_policy_block.search(line):
                in_policy_block = True
            
            # We are entering a subconfig inside a ssl-vpn action and we want to skip it
            if inspect_next_ssl_vpn_command and not(p_entering_subpolicy_block.search(line)):
                skip_ssl_vpn_policy_block = False
                inspect_next_ssl_vpn_command = False
            
            elif inspect_next_ssl_vpn_command and p_entering_subpolicy_block.search(line):
                inspect_next_ssl_vpn_command = False
                skip_ssl_vpn_policy_block = True
            
            # We are in a policy block
            if in_policy_block:
                if p_policy_number.search(line) and not(skip_ssl_vpn_policy_block):
                    policy_number = p_policy_number.search(line).group('policy_number')
                    policy_elem[u'id'] = policy_number
                    if not('id' in order_keys):
                        order_keys.append(u'id')
                
                # We match a setting
                if p_policy_set.search(line) and not(skip_ssl_vpn_policy_block):
                    policy_key = p_policy_set.search(line).group('policy_key')
                    if not(policy_key in order_keys):
                        order_keys.append(policy_key)
                    
                    policy_value = p_policy_set.search(line).group('policy_value').strip()
                    
                    if len(iface_alias) > 0  and (policy_key == 'srcintf' or policy_key == 'dstintf'):
                        policy_elem[policy_key] = iface_alias[policy_value]
                    elif policy_key == 'srcaddr' or policy_key == 'dstaddr' or policy_key == 'service':
                        policy_elem[policy_key] = shlex.split(policy_value, " ")
                    else:
                        policy_value = re.sub('["]', '', policy_value)
                        policy_elem[policy_key] = policy_value
                    if policy_key == 'action' and policy_value == 'ssl-vpn':
                        inspect_next_ssl_vpn_command = True
                        skip_ssl_vpn_policy_block = True
                
                # We are done with the current policy id
                if p_policy_next.search(line) and not(skip_ssl_vpn_policy_block):
                    policy_list.append(policy_elem)
                    policy_elem = {}
                    
            
            # We are exiting the policy block
            if p_exiting_policy_block.search(line):
                if skip_ssl_vpn_policy_block == True:
                    skip_ssl_vpn_policy_block = False
                else:
                    in_policy_block = False
    
    return (policy_list, order_keys)


def generate_csv(results, keys, options):
    """
        Generate a plain csv file
    """
    if results and keys:
        with io.open(options.output_file, mode=fd_write_options, encoding=options.output_encoding) as fd_output:
            spamwriter = csv.writer(fd_output, delimiter=options.delimiter, quoting=csv.QUOTE_ALL, lineterminator='\n')
            
            if not(options.skip_header):
                spamwriter.writerow(keys)
            
            for policy in results:
                output_line = []
                
                for key in keys:
                    if key in policy.keys():
                        if isinstance(policy[key], list):
                            output_line.append("\n".join(policy[key]))
                        else:
                            output_line.append(policy[key])
                    else:
                        output_line.append('')
            
                spamwriter.writerow(output_line)
                if options.newline:
                    spamwriter.writerow('')
        
        fd_output.close()
    
    return None

def main():
    """
        Dat main
    """
    global parser
    
    options, arguments = parser.parse_args()
    
    if (options.input_file == None):
        parser.error('Please specify a valid input file')
    
    if (sys.version_info < (3, 0)):
        options.output_encoding = None
    
    if (options.parse_iface_alias):
        iface_alias = parse_iface_alias(options)
        #print(iface_alias)
    else:
        iface_alias = {}
    
    results, keys = parse(options, iface_alias)
    generate_csv(results, keys, options)
    
    return None

if __name__ == "__main__" :
    main()