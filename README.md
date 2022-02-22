# SunloginBatchRCE
向日葵RCE漏洞检测的相关脚本

usage: sunloginRCEBatchScan.py [-h] [-i IP] [-p PORTS] [-v] [-c CMD] [-x PROXIES]

    Sun Login RCE CMD ...

    optional arguments:
      -h, --help            show this help message and exit
      -i IP, --ip IP        输入目标IP、目标IP段、目标IP范围
      -p PORTS, --ports PORTS
                            输入目标端口、目标端口范围
      -v, --verify          是否验证Cookie获取和命令执行
      -c CMD, --cmd CMD     批量命令执行时使用的命令
      -x PROXIES, --proxies PROXIES
                            通过代理进行请求，支持Socks5和HTTP, 例如: http://127.0.0.1:8080 or socks5://127.0.0.1:1080
                            


usage: sunloginRCE.py [-h] [-i HOST] [-p PROXIES]

Sun Login RCE CMD ...

    optional arguments:
      -h, --help            show this help message and exit
      -i HOST, --host HOST  Specifies a ip:port
      -p PROXIES, --proxies PROXIES
                            Specify the requests proxy address, support Socks5 and HTTP, for example: http://127.0.0.1:8080 or
                            socks5://127.0.0.1:1080
                           
                           
Usage: sunloginRCE+.py [-h] [-i HOST] [-p PROXIES] [-g GET]

optional arguments:
  -h, --help            show this help message and exit
  -i HOST, --host HOST  Specifies a ip:port
  -p PROXIES, --proxies PROXIES
                        Specify the requests proxy address, support Socks5 and HTTP, for example: http://127.0.0.1:8080 or
                        socks5://127.0.0.1:1080
  -g GET, --get GET     Get server ip:port,The default path:C:\ProgramData\Oray\SunloginClient\log
  



