# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     test
   Description :
   Author :       Ntears
   date：          2018/8/16
-------------------------------------------------
   Change Activity:
                   2018/8/16:
-------------------------------------------------
"""
__author__ = 'Ntears'

import requests
import json
import re
import random
import base64
import sys
reload(sys)
sys.setdefaultencoding('utf-8') 
config = {"Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html）",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html) ",
            "Googlebot/2.1 (+http://www.googlebot.com/bot.html) ",
            "Googlebot/2.1 (+http://www.google.com/bot.html) ",
            "Mozilla/5.0 (compatible; Yahoo! Slurp China; http://misc.yahoo.com.cn/help.html”) ",
            "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp”) ",
            "iaskspider/2.0(+http://iask.com/help/help_index.html”) ",
            "Mozilla/5.0 (compatible; iaskspider/1.0; MSIE 6.0) ",
            "Sogou web spider/3.0(+http://www.sogou.com/docs/help/webmasters.htm#07″) ",
            "Sogou Push Spider/3.0(+http://www.sogou.com/docs/help/webmasters.htm#07″) ",
            "Mozilla/5.0 (compatible; YodaoBot/1.0; http://www.yodao.com/help/webmaster/spider/”; ) ",
            "msnbot/1.0 (+http://search.msn.com/msnbot.htm”)",
            "Mozilla/5.0 (Linux;u;Android 4.2.2;zh-cn;) ",
            "AppleWebKit/534.46 (KHTML,like Gecko) Version/5.1 Mobile Safari/10600.6.3 ",
            "(compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html）",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.87 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.87 Safari/537.36 OPR/37.0.2178.32",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/534.57.2 (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2486.0 Safari/537.36 Edge/13.10586",
            "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.106 BIDUBrowser/8.3 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Maxthon/4.9.2.1000 Chrome/39.0.2146.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.80 Safari/537.36 Core/1.47.277.400 QQBrowser/9.4.7658.400",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 UBrowser/5.6.12150.8 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.122 Safari/537.36 SE 2.X MetaSr 1.0",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.154 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36 TheWorld 7"}



def getJson(url,cursor="",pan="1"):
    func = ""
    if pan == "1":#ip反查 and 域名反查
        if re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}$", url):
            url = "https://www.virustotal.com/ui/ip_addresses/%s/resolutions?cursor=%s"%(url,cursor)
        else:
            url = "https://www.virustotal.com/ui/domains/%s/resolutions?cursor=%s"%(url,cursor)
    if pan == "2":#二级域名
        url = "https://www.virustotal.com/ui/domains/%s/subdomains" % (url)
    #判断递归url   
    if pan == "1":
        return getHost(url)
    if pan == "2":
        return getSubdomains(url)

listJson = []
#ip反查
def getHost(url):
    headers = {"user-agent": random.choice(list(config))}
    req = requests.get(url, verify=True, headers=headers)
    try:
        js = json.loads(req.text)
        for val in js['data']:
             listJson.append(val['attributes'])
        next = js['links']['next']
        getHost(next) #递归
    except KeyError:
        pass



#二级域名
def getSubdomains(url):
   # url = "https://www.virustotal.com/ui/domains/%s/subdomains"%(url)
    headers = {"user-agent": random.choice(list(config))}
    req = requests.get(url, verify=True, headers=headers)
    try:
        js = json.loads(req.text)
        for val in js['data']:
            listJson.append(val['id'])
        next = js['links']['next']
        getSubdomains(next) #递归
    except KeyError:
        pass


def getip_address(ip):
	headers = {"user-agent": random.choice(list(config))}
	req = requests.get("http://ip.soshoulu.com/ajax/shoulu.ashx?_type=ipsearch&ip="+str(ip),headers=headers)
	return str(req.text).split('$')[0].encode(encoding='GBK',errors='strict')+"\t"+str(ip)

def show():
    banner ="CiBfICAgXyBfICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBfICAgICAgICAgICAgICAgICAgICAgICBfICAgICAgIAp8IFwgfCB8IHxfIF9fXyAgX18gXyBfIF9fIF9fXyAgICAgICAgX198IHwgX19fICBfIF9fIF9fXyAgIF9fIF8oXylfIF9fICAKfCAgXHwgfCBfXy8gXyBcLyBfYCB8ICdfXy8gX198X19fX18gLyBfYCB8LyBfIFx8ICdfIGAgXyBcIC8gX2AgfCB8ICdfIFwgCnwgfFwgIHwgfHwgIF9fLyAoX3wgfCB8ICBcX18gXF9fX19ffCAoX3wgfCAoXykgfCB8IHwgfCB8IHwgKF98IHwgfCB8IHwgfAp8X3wgXF98XF9fXF9fX3xcX18sX3xffCAgfF9fXy8gICAgICBcX18sX3xcX19fL3xffCB8X3wgfF98XF9fLF98X3xffCB8X3wK"
    print base64.b64decode(banner)
    print "Usage: test.py baidu.com 1\t|| 1 is IP anti inspection\t|| 2 is Subdomains"
if __name__ == "__main__":
    if(len(sys.argv)<3):
        show()
        sys.exit(0)
    if  str(sys.argv[2])=="2":
        getJson(str(sys.argv[1]), pan=str(sys.argv[2]))
        for val in listJson:
            print "%s"%(val)
    if  str(sys.argv[2])=="1":
    	getJson(str(sys.argv[1]), pan=str(sys.argv[2]))
        if re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}$",str(sys.argv[1])):
            for val in listJson:
                print "%s"%(val['host_name']) 	
        else:
            for val in listJson:
                print "%s"%(getip_address(str(val['ip_address'])))
