import requests
import json
import time
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# awvs

# awvs_url = "https://192.168.2.213:3443"
Cookie = "ui_session=2986ad8c0a5b3df4d7028d5f3c06e936c5ed74164e1863b0cc1394bb38e9ce4a09df26d8477c83df670ecaccbdd50028ff6cbcccecd1e78ebc8fb8c44a5b62e2a"
mod_id = {
    "full_scan": "11111111-1111-1111-1111-111111111111",
    "high_risk_vul": "11111111-1111-1111-1111-111111111112",
    "cross_site_vul": "11111111-1111-1111-1111-111111111116",
    "sql_inject_vul": "11111111-1111-1111-1111-111111111113",
    "week_pass_vul": "11111111-1111-1111-1111-111111111115",
    "crawl_only" : "11111111-1111-1111-1111-111111111117",
    "malware_scan": "11111111-1111-1111-1111-111111111120" 
}

mod = mod_id['crawl_only']

# 扫描器速度
speed = "slow"

# xray
xray_proxy_ip = "172.17.0.3"
xray_proxy_port = "1111"


headersjson = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:73.0) Gecko/20100101 Firefox/73.0",
    "Content-Type": "application/json;charset=UTF-8",
    "X-Auth": Cookie[11:],
    "Origin": awvs_url,
    "Referer": awvs_url,
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "cors",
    "Accept": "application/json, text/plain, */*",
    "Cookie": Cookie
}


def add_from_file():
    fileone = open('url.txt', 'r+')
    for i in fileone:
        urls = i.replace('\n', '')
        url = awvs_url + "/api/v1/targets"
        datajson = {
            'address': urls,
                'description': '',
                'criticality': '10'
        }
        try:
            res = requests.post(url, headers=headersjson,verify=False, data=json.dumps(datajson))
            respa = res.headers
            print("[+] " + urls + " 添加成功")
            print(res)
        except:
            print("[-] " + urls + " 添加失败! " + url + "接口请求失败")
            pass
        try:
            respa = respa['Location']
        except:
            pass
        if "/api/v1/targets/" in respa:
            respa = respa.replace('/api/v1/targets/', '')
            set_proxy(urls, respa)
        else:
            pass


def set_proxy(target_url,locationone):
    url = awvs_url + '/api/v1/targets/'+locationone+'/configuration'

    datajson = {
        "enabled": "true",
        "address": xray_proxy_ip,
            "protocol": "http",
            "port": xray_proxy_port
    }

    datajsontwo = {
        "proxy": datajson,
        "scan_speed": speed
    }


    try:
        res = requests.patch(url, headers=headersjson, verify=False,data=json.dumps(datajsontwo))
        if(res.status_code == 204):
            print("[+] " + target_url + " 代理设置成功")
    except:
        print("[-] " + target_url + " 代理设置失败")
        pass
    try:
        set_scanmod(target_url,locationone)
    except:
        pass

def set_scanmod(target_url,locationone):
    url = awvs_url + "/api/v1/scans"
    datajsona = {
        "disable": "false",
            "start_date": None,
            "time_sensitive": "false"
    }

    datajson = {
        "target_id": locationone,
            "profile_id": mod,
            "schedule": datajsona,
            "ui_session_id": "c45eab520de7822aa55c71ad71688136"
    }
    try:
        res = requests.post(url, headers=headersjson, verify=False,data=json.dumps(datajson))
        if res.status_code == 201:
            print("[+] " + target_url + " 设置成功,开始扫描")
        respa = res.headers
        respa = respa['Location']
    except:
        pass
    if "/api/v1/scans/" in respa:
        respa = respa.replace('/api/v1//scans/', '')
        urls = awvs_url + "/api/v1/scans/"+respa
        res = requests.get(urls, headers=headersjson, verify=False)
    else:
        pass


if __name__ == '__main__':
    add_from_file()
