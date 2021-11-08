import yaml
import requests
import time

shadowrocket_rules = {
    'General': {
        'bypass-system': 'true',
        'skip-proxy': '192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, captive.apple.com',
        'bypass-tun': '10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 255.255.255.255/32',
        'dns-server': 'system, 8.8.8.8, 8.8.4.4',
        'ipv6': 'true'
    },
    'Rule': [],
    'Host': {
        'localhost': '127.0.0.1'
    },
    'URL Rewrite': [
        '^http://(www.)?g.cn https://www.google.com 302',
        '^http://(www.)?google.cn https://www.google.com 302'
    ]
}

rule_providers = {
    'reject': {
        'behavior': 'DOMAIN-SUFFIX',
        'url': 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt'
    },
    'icloud': {
        'behavior': 'DOMAIN-SUFFIX',
        'url': 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/icloud.txt'
    },
    'apple': {
        'behavior': 'DOMAIN-SUFFIX',
        'url': 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/apple.txt'
    },
    'google': {
        'behavior': 'DOMAIN-SUFFIX',
        'url': 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/google.txt'
    },
    'proxy': {
        'behavior': 'DOMAIN-SUFFIX',
        'url': 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/proxy.txt'
    },
    'direct': {
        'behavior': 'DOMAIN-SUFFIX',
        'url': 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/direct.txt'
    },
    'private': {
        'behavior': 'DOMAIN-SUFFIX',
        'url': 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/private.txt'
    },
    'gfw': {
        'behavior': 'DOMAIN-SUFFIX',
        'url': 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/gfw.txt'
    },
    'greatfire': {
        'behavior': 'DOMAIN-SUFFIX',
        'url': 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/greatfire.txt'
    },
    'tld-not-cn': {
        'behavior': 'DOMAIN-SUFFIX',
        'url': 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/tld-not-cn.txt'
    },
    'telegramcidr': {
        'behavior': 'IP-CIDR',
        'url': 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/telegramcidr.txt'
    },
    'cncidr': {
        'behavior': 'IP-CIDR',
        'url': 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/cncidr.txt'
    },
    'lancidr': {
        'behavior': 'IP-CIDR',
        'url': 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/lancidr.txt'
    }
}

rules = {
    'blacklist': {
        'private': 'DIRECT',
        'reject': 'REJECT',
        'tld-not-cn': 'PROXY',
        'gfw': 'PROXY',
        'greatfire': 'PROXY',
        'telegramcidr': 'PROXY',
        'FINAL': 'DIRECT'
    },
    'whitelist': {
        'private': 'DIRECT',
        'reject': 'REJECT',
        'icloud': 'DIRECT',
        'apple': 'DIRECT',
        'google': 'DIRECT',
        'proxy': 'PROXY',
        'direct': 'DIRECT',
        'lancidr': 'DIRECT',
        'cncidr': 'DIRECT',
        'telegramcidr': 'PROXY',
        'FINAL': 'PROXY'
    }
}


def get_domains_and_ips():
    for k in rule_providers:
        req = requests.get(rule_providers[k]['url'])
        data = yaml.safe_load(req.content)
        data = data['payload']
        data = [item[2:] if item.startswith('+.') else item for item in data]
        rule_providers[k]['domains_ips'] = data


def convert_config(rule_name):
    with open('./{}.conf'.format(rule_name), 'w') as f:
        f.write('# converted from https://github.com/Loyalsoldier/clash-rules\n')
        f.write('# update time: {}\n'.format(time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime())))
        for item in shadowrocket_rules:
            f.write('[{}]\n'.format(item))
            if item == 'Rule':
                for provider, mode in rules[rule_name].items():
                    if provider == 'FINAL':
                        f.write('FINAL, {}\n'.format(mode))
                        continue
                    for domain_ip in rule_providers[provider]['domains_ips']:
                        f.write('{},{},{}\n'.format(
                            rule_providers[provider]['behavior'], domain_ip, mode))
            else:
                if isinstance(shadowrocket_rules[item], dict):
                    for k, v in shadowrocket_rules[item].items():
                        f.write('{} = {}\n'.format(k, v))
                else:
                    for k in shadowrocket_rules[item]:
                        f.write('{}\n'.format(k))


if __name__ == '__main__':
    get_domains_and_ips()
    for item in rules:
        convert_config(item)
