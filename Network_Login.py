#-*- coding:utf-8 -*-
__author__="张云飞，张鹏飞，黎明波"
import sys
import requests
import re
from datetime import datetime

# 加密函数
def encrypt(password, secret_key='drcom'):
    """
    :param password: 需要加密的原始密码
    :param secret_key: 自定义密钥（encryption_type='1'时生效）
    :return: 包含加密结果的字典
    """

    def getkey(key_str: str) -> int:
        """生成密钥（基于字符串的异或运算）"""
        ret = 0
        for c in key_str:
            ret ^= ord(c)
        return ret

    def enc_pwd(pass_in: str, key: int) -> str:
        """密码加密：异或处理+16进制转换"""
        if not pass_in:
            return ""
        if len(pass_in) > 512:
            return "-1"

        pass_out = ""
        for c in pass_in:
            ch = ord(c) ^ key
            # 转为两位16进制字符串，大写转小写，补前导零
            hex_str = hex(ch)[2:].zfill(2)
            pass_out += hex_str
        return pass_out

    # 生成密钥
    key = getkey(secret_key)

    # 加密密码
    encrypted_pwd = enc_pwd(password, key)
    return encrypted_pwd


# 登录类
class Login:
    def __init__(self):
        pass

    def login(self, url):
        if self.is_connected()==False:
            print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} 网络断开，重新连接...")
            
            # 获取当前IP地址
            try:
                response = requests.get('https://drcom.tyut.edu.cn/', timeout=10)
                pattern = r"v46ip='([^']*)'"
                match = re.search(pattern, response.text)
                if match:
                    v46ip = match.group(1).strip()
                    print(f"当前IP地址为: {v46ip}")
                    url = re.sub(r'wlan_user_ip=[^&]*', f'wlan_user_ip={encrypt(v46ip)}', url)
                else:
                    print("获取IP地址失败")
            except requests.exceptions.RequestException as e:
                print(f"Request failed: {e}", file=sys.stderr)

            #消息头，Request Header粘过来
            post_headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "Accept-Encoding":"gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Connection": "keep-alive",
            "Cookie":"PHPSESSID=iartgtqsnm4i3fg270pkmk2en1",
            "Host": "219.226.127.250:802",
            "Referer":"https://drcom.tyut.edu.cn/",
            "Upgrade-Insecure-Requests":"1",
            "User-Agent":"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36",
            }
            
            #数据包，查询字符串参数粘过来
            post_data={
            "c": "ACSetting",
            "a": "Login",
            "protocol": "http:",
            "hostname": "219.226.127.250",
            "port": "",
            "iTermType":"1",
            "wlanuserip": "",
            "wlanacip": "",
            "wlanacname":"" ,
            "redirect": "",
            "session": "",
            "ssid": "",
            "vlanid":"" ,
            "queryACIP":"0",
            "jsVersion": "1.3.8",
            "DDDDD": ",0,maxuetao1427",
            "upass": "DDom3813",
            "R1": "0",
            "R2": "",
            "R6": "0",
            "v6ip": "",
            "para": "00",
            "0MKKey": "123456"
                }
            
            #提交表单
            try:
                requests.get(url,headers=post_headers,data=post_data) 
                if self.is_connected()==True:
                    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} 连接成功")
                else:
                    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} 脚本失效，请重新get抓包，修改--url参数")
            except Exception as e:
                print(e)
                print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} 连接失败，请检查网络")

    #ping百度，确认网络连接状态
    def is_connected(self):
        try:
            test=requests.get("https://www.baidu.com",timeout=5)
            if test.status_code==200:
                return True
            else:
                return False
        except Exception as e:
            print(e)
            return False

if __name__=="__main__":
    """
    使用说明：

    方法一：
    ①将学生号，密码分别填写到user_account, user_password变量中
    ②添加crontab测试任务：* * * * * /usr/bin/python3 ~/cron_test/test_reboot.py >> ~/cron_test/cron.log 2>&1

    方法二：
    ①在网页端将登录过程的login get url复制下来，赋值给url变量，参考：https://zhuanlan.zhihu.com/p/370801224
    ②添加crontab测试任务：* * * * * /usr/bin/python3 ~/cron_test/test_reboot.py >> ~/cron_test/cron.log 2>&1
    """
    
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} 校园网登陆脚本运行中...")
    user_account = ""
    user_password = ""
    url = f"https://drcom.tyut.edu.cn:802/eportal/portal/login?callback=130546474740&login_method=46&user_account={encrypt(user_account)}&user_password={encrypt(user_password)}&wlan_user_ip=46474659405946434f59464644&wlan_user_ipv6=&wlan_user_mac=474747474747474747474747&wlan_ac_ip=&wlan_ac_name=&mac_type=47&authex_enable=&jsVersion=435944&terminal_type=46&lang=1219&user_agent=3a180d1e1b1b1658425947575f201e191318000457392357464759474c57201e1941434c570f41435e573607071b122012153c1e0358424440594441575f3c3f233a3b5b571b1e1c12573012141c185e57341f05181a12584643455947594759475724161116051e584244405944415732131058464345594759475947&enable_r3=47&encrypt=1&v=1921&lang=en"
    # url = "https://drcom.tyut.edu.cn:802/eportal/portal/login?callback=130546474740&login_method=46&user_account=4547424e&user_password=0606464430d5959&wlan_user_ip=464746594059464644&wlan_user_ipv6=&wlan_user_mac=474747474747474747474747&wlan_ac_ip=&wlan_ac_name=&mac_type=47&authex_enable=&jsVersion=435944&terminal_type=46&lang=1219&user_agent=3a180d1e1b1b1658425947575f201e191318000457392357464759474c57201e1941434c570f41435e573607071b122012153c1e0358424440594441575f3c3f233a3b5b571b1e1c12573012141c185e57341f05181a12584643455947594759475724161116051e584244405944415732131058464345594759475947&enable_r3=47&encrypt=1&v=1921&lang=en"
    login=Login()
    login.login(url)


