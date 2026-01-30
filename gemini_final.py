#!/usr/bin/env python3
import requests
import socket
import os
import ssl
import time
import getpass
import re
from datetime import datetime
from urllib.parse import urlparse
from colorama import Fore, Style, init

# تهيئة الألوان
init(autoreset=True)

# --- إعدادات الأمان ---
ADMIN_PASSWORD = "msy"  # يمكنك تغيير كلمة السر من هنا
SECOND_PASSWORD ="mos"

BANNER = f"""
{Fore.CYAN}
  ██████  ███████ ███    ███ ██ ███    ██ ██ 
 ██       ██      ████  ████ ██ ████   ██ ██ 
 ██   ███ █████   ██ ████ ██ ██ ██ ██  ██ ██ 
 ██    ██ ██      ██  ██  ██ ██ ██  ██ ██ ██ 
  ██████  ███████ ██      ██ ██ ██   ████ ██ 
         Security Intelligent Tool V4.0 (PRO)
{Fore.WHITE}-------------------------------------------------------
{Fore.YELLOW}          المساعد الذكي للأمن السيبراني - كالي لينكس
{Fore.WHITE}-------------------------------------------------------{Style.RESET_ALL}"""

def speak(text):
    """وظيفة التحدث الصوتي"""
    os.system(f'espeak "{text}" &')

def log_result(data):
    """حفظ النتائج في تقرير خارجي"""
    with open("scan_report.txt", "a", encoding="utf-8") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {data}\n")

# --- نظام تسجيل الدخول ---
def login_screen():
    os.system('clear')
    print(BANNER)
    print(f"{Fore.YELLOW}🔒 هذه الأداة محمية. يرجى إثبات هويتك.")
    
    attempts = 3
    while attempts > 0:
        # getpass تخفي كلمة السر أثناء الكتابة
        pwd = getpass.getpass(f"{Fore.CYAN}أدخل كلمة مرور المسؤول: {Style.RESET_ALL}")
        if pwd == ADMIN_PASSWORD or pwd == SECOND_PASSWORD:
            print(f"{Fore.GREEN}\n[✅] تم التحقق بنجاح! جاري تحميل النظام...")
            time.sleep(1)
            return True
        else:
            attempts -= 1
            print(f"{Fore.RED}[❌] كلمة مرور خاطئة! تبقى لديك ({attempts}) محاولات.")
    
    print(f"{Fore.RED}\n[!] تم حظر الوصول غير المصرح به.")
    return False

# --- وظائف الفحص ---

def web_scan():
    url = input(f"{Fore.BLUE}🔗 أدخل رابط الموقع (مثال: google.com): ")
    if not url.startswith('http'): url = 'https://' + url
    print(f"{Fore.YELLOW}🔍 جاري فحص الرؤوس الأمنية لـ {url}...")
    try:
        r = requests.get(url, timeout=5)
        headers = {"X-Frame-Options": "Clickjacking", "Content-Security-Policy": "XSS", "X-Content-Type-Options": "Sniffing"}
        for h, desc in headers.items():
            status = f"{Fore.GREEN}[✅] مؤمن" if h in r.headers else f"{Fore.RED}[❌] معرض لثغرة {desc}"
            print(f"{h}: {status}")
    except: print(f"{Fore.RED}[!] تعذر الوصول للموقع.")

def check_ssl():
    host = input(f"{Fore.BLUE}🛡️ أدخل الدومين لفحص التشفير: ")
    if "://" in host: host = urlparse(host).netloc
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                print(f"{Fore.GREEN}[✅] البروتوكول: {ssock.version()} | القوة: {cipher[2]} bits")
    except: print(f"{Fore.RED}[!] فشل فحص SSL.")

def check_malicious_link():
    link = input(f"{Fore.BLUE}🔗 أدخل الرابط لتحليله: ")
    suspicious = ["login", "free", "gift", "verify", "update"]
    is_bad = any(word in link.lower() for word in suspicious)
    try:
        res = requests.get(link, timeout=5, allow_redirects=True)
        if is_bad or len(res.history) > 1:
            print(f"{Fore.RED}[⚠️] تحذير: الرابط مشبوه أو يحتوي تحويلات مخفية!")
        else: print(f"{Fore.GREEN}[✅] الرابط يبدو آمناً.")
    except: print(f"{Fore.RED}[!] تعذر تحليل الرابط.")

def network_scan():
    from scapy.all import ARP, Ether, srp
    ip_range = input(f"{Fore.BLUE}🌐 نطاق الشبكة (192.168.1.1/24): ")
    print(f"{Fore.YELLOW}📡 جاري فحص الأجهزة المتصلة...")
    try:
        result = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range), timeout=2, verbose=0)[0]
        for _, rcved in result: print(f"{Fore.GREEN}IP: {rcved.psrc} | MAC: {rcved.hwsrc}")
    except: print(f"{Fore.RED}[!] يرجى التشغيل بـ sudo.")

def phone_scan():
    ip = input(f"{Fore.BLUE}📱 أدخل IP الهاتف: ")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    if s.connect_ex((ip, 5555)) == 0:
        print(f"{Fore.RED}[⚠️] خطر: منفذ ADB مفتوح! الهاتف معرض للاختراق.")
    else: print(f"{Fore.GREEN}[✅] الهاتف مؤمن من منفذ ADB.")
    s.close()

def password_check():
    print(Fore.YELLOW + "\n[*] اختبار قوة كلمة المرور (باستخدام re)...")
    pwd = getpass.getpass("ادخل كلمة المرور للاختبار: ")
    
    # حساب القوة يدوياً
    score = 0
    if len(pwd) >= 8: score += 1
    if re.search(r"[A-Z]", pwd): score += 1
    if re.search(r"\d", pwd): score += 1
    if re.search(r"[@#$%^&+=]", pwd): score += 1
    
    levels = ["ضعيفة جداً", "ضعيفة", "متوسطة", "قوية", "قوية جداً"]
    print(f"{Fore.CYAN}القوة التقديرية: {levels[score]} ({score}/4)")
    input("\nاضغط Enter للعودة للقائمة...")

# --- الدالة الرئيسية ---

def main():
    if not login_screen():
        return

    os.system('clear')
    print(BANNER)
    
    # ترحيب صوتي عند الدخول الناجح
    speak("Access granted. Welcome back commander. How can I help you today?")
    
    print(f"{Fore.GREEN}مرحباً بك في أداة الفحص الذكية!")
    print(f"{Fore.WHITE}أنا مساعدك الأمني، جاهز لتنفيذ المهام المطلوبة.\n")

    while True:
        print(f"{Fore.CYAN}القائمة الرئيسية للمهام:")
        print(f"{Fore.WHITE}---------------------------------------------")
        print(f"{Fore.MAGENTA} 1 {Fore.WHITE}>> فحص ثغرات المواقع (Web)")
        print(f"{Fore.MAGENTA} 2 {Fore.WHITE}>> فحص قوة تشفير المواقع (SSL)")
        print(f"{Fore.MAGENTA} 3 {Fore.WHITE}>> فحص الروابط (كشف التلغيم)")
        print(f"{Fore.MAGENTA} 4 {Fore.WHITE}>> فحص الشبكة (اكتشاف الأجهزة)")
        print(f"{Fore.MAGENTA} 5 {Fore.WHITE}>> فحص الهواتف (ثغرة ADB)")
        print(f"{Fore.MAGENTA} 6 {Fore.WHITE}>> اختبار قوة كلمة المرور")
        print(f"{Fore.RED} 0 {Fore.WHITE}>> إغلاق الأداة")
        print(f"{Fore.WHITE}---------------------------------------------")

        choice = input(f"\n{Fore.CYAN}بانتظار أمرك >> {Style.RESET_ALL}")
        
        if choice == '1': web_scan()
        elif choice == '2': check_ssl()
        elif choice == '3': check_malicious_link()
        elif choice == '4': network_scan()
        elif choice == '5': phone_scan()
        elif choice == '6': password_check()
        elif choice == '0':
            speak("Goodbye and stay safe")
            print(f"{Fore.YELLOW}\nتم تسجيل الخروج. ابقَ آمناً!")
            break
        else:
            print(f"{Fore.RED}[!] خيار غير صحيح.")

if __name__ == "__main__":
    main()
