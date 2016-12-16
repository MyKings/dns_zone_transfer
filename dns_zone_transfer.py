#!/usr/bin/env python
# coding: utf-8
# author: MyKings

"""
$ nmap --script dns_zne_transfer.nse --script-args dns_zone_transfer.domain dns.xxx.com -p 53 -Pn xxx.com
$ dig @dns.xxx.com axfr xxx.com
"""

from __future__ import unicode_literals

import os
import argparse
import subprocess
import re


# gTLD and nTLD
domains_zone = {'gTLD': [], 'nTLD': []}


def init_domains_zone():
    """
    initialization domains zone
    refers: https://www.iana.org/domains/root/db
    """
    file_path_obj = {
        'gTLD': './var/gTLD.txt',
        'nTLD': './var/nTLD.txt',
    }
    for tld, tld_path in file_path_obj.iteritems():
        with open(tld_path, 'rb') as fp:
            for line in fp:
                # TODO ascii -> utf-8 or unicode
                domains_zone[tld].append(line.strip())
            domains_zone[tld] = set(domains_zone[tld])


def get_sld(domain):
    """
    Get SLD
    :param domain: full domain name
                   eg: www.google.com -> google.com
                       www.admin.com.cn. -> admin.com.cn
                       www.admin.cn -> admin.cn
                       admin.cn. -> admin.cn
                       blog.it.team.develop.admin.cn. -> admin.cn
    :return: SLD
    """
    result = ''
    domain_fragment = domain.split('.')
    top_block = ''
    second_block = ''
    third_block = ''

    if domain_fragment and domain.endswith('.'):
        # TLD direct return
        if len(domain_fragment) == 3:
            return domain

        top_block = domain_fragment[-2]
        second_block = domain_fragment[-3]
        # www.xxx.edu.cn.
        if len(domain_fragment) > 4:
            third_block = domain_fragment[-4]
    else:
        top_block = domain_fragment[-1]
        second_block = domain_fragment[-2]
        if len(domain_fragment) > 3:
            third_block = domain_fragment[-3]

    if domains_zone['gTLD'] and domains_zone['nTLD']:
        # www.google.com.hk -> .hk
        if '.%s' % top_block in domains_zone['nTLD']:
            result = '.%s' % top_block
        else:
            # www.google.com -> google.com
            return '%s.%s' % (second_block, top_block)

        # www.geloogle.com.hk -> .com
        if '.%s' % second_block in domains_zone['gTLD']:
            result = '%s%s' % (second_block, result)
        else:
            # www.admin.cn -> admin.cn
            result = '%s%s' % (second_block, result)

        if third_block:
            result = '%s.%s' % (third_block, result)

    return result


def parser_cmd():
    """
    command line interface
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', help='List of domain name files to check.')
    parser.add_argument('-d',dest='domain', help='The domain name to be detected. eg: www.google.com')
    parser.add_argument('-o', dest='output', action='store_true', help='The resulting output file. default: False')
    parser.add_argument('-s', dest='server', help='Manually select a dns server.')
    conf = parser.parse_args()
    if conf.domain or conf.f:
        return conf
    else:
        parser.print_help()
        exit(1)


def test_dns_zone_transfer(domain):
    """
    test dns zone transfer vulnerability
    """
    sld = get_sld(domain)
    cmd = 'nslookup -type=ns %s' % sld
    if conf.server:
        cmd = '%s %s' % (cmd, conf.server)
    print('[*] `%s`' % cmd)
    pipe = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout
    cmd_result = pipe.read()
    ns_list = re.findall('nameserver = (.+)', cmd_result)
    if ns_list:
        print('[*] Name Server: %s' % ns_list)
        for ns in ns_list:
            pipe = subprocess.Popen('dig @%s axfr %s' % (ns, sld), shell=True, stdout=subprocess.PIPE).stdout
            cmd_result = pipe.read()
            if 'XFR size' in cmd_result:
                print('[+] 🍺 🍺 🍺  Discover vulnerability. NS:[%s], DOMAIN:[%s]' % (ns, sld))
                if conf.output:
                    file_name = '%s_result.txt' % sld
                    with open(file_name, 'w+') as fp:
                        fp.write(cmd_result)
                    print("[*] The resulting file %s succeeds." % file_name)
    else:
        print('%s\n[-] "%s" the query failed!' % (cmd_result, sld))


def main(conf):
    """
    main method
    """
    if conf.domain:
        test_dns_zone_transfer(conf.domain)
    elif conf.f:
        if os.path.isfile(conf.f):
            # TODO -o Modify the export method
            with open(conf.f) as fp:
                for line in fp:
                    test_dns_zone_transfer(line.strip())
        else:
            print('[-] % file not found!' % conf.f)


if __name__ == '__main__':
    init_domains_zone()
    """
    examples = (
        'www.google.com',
        'www.admin.com.cn.',
        'www.admin.cn',
        'admin.cn.',
        'blog.it.team.develop.admin.cn.'
    )
    for domain in examples:
        print domain, ' -> ', get_sld(domain)
    """
    conf = parser_cmd()
    main(conf)
