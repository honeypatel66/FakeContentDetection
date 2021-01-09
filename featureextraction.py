from urllib.parse import urlparse
from urllib import parse
import urllib
import favicon
import requests
import whois
import numpy as np
import scipy as sc
import pandas as pd 
from fractions import Fraction
import  pythonwhois
import validators
import socket
import re
import datetime
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver import ActionChains
from sklearn.ensemble import RandomForestClassifier,RandomForestRegressor
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import numpy as  np
import pandas as pd


def start_url(url):
    if not parse.urlparse(url.strip()).scheme:
        url = 'http://' + url
    protocol, host, path, params, query, fragment = parse.urlparse(url.strip())

    result = {
        'url': host + path + params + query + fragment,
        'protocol': protocol,
        'host': host,
        'path': path,
        'params': params,
        'query': query,
        'fragment': fragment
    }
    return result

def valid_ip(host):
    try:
        ipadd = socket.gethostbyname(host)
        return 1
    except Exception:
        return -1

def length(url):
    lg =len(url)
    if(lg<54):
        return 1
    elif(lg>=54 and lg<=74):
        return 0
    else:
        return -1
    
    


def find_SSL(url):
    try:
        requests.get(url, verify=True)
        return 1
    except Exception:
        return -1

def check_shortener(url):
    file = open('D:\\Codes\\Sem 7\\PMMS\\Implementation\\shortners.txt', 'r')
    for line in file:
        with_www = "www." + line.strip()
        if line.strip() == url['host'].lower() or with_www == url['host'].lower():
            file.close()
            return 1
    file.close()
    return -1

def check_at_symbol(url):
    if ("@" in url):
        return 1
    else:
        return -1

def check_double_slash(url):
    try:
        find_ind=url.index("//",7)
        return 1
    except Exception:
        return -1

def check_domain_dash(url):
    domain = urlparse(url).netloc
    if("-" in domain):
        return 1
    else:
        return -1

def check_tld(text):
    file = open('tlds.txt', 'r')
    pattern = re.compile("[a-zA-Z0-9.]")
    for line in file:
        i = (text.lower().strip()).find(line.strip())
        while i > -1:
            if ((i + len(line) - 1) >= len(text)) or not pattern.match(text[i + len(line) - 1]):
                file.close()
                return 1
            i = text.find(line.strip(), i + 1)
    file.close()
    return -1

def expiration_date_register(url):
    if url['host'].startswith("www."):
        url['host'] = url['host'][4:]

    pythonwhois.net.socket.setdefaulttimeout(3.0)
    try:
        result_whois = pythonwhois.get_whois(url['host'].lower())
        if not result_whois:
            return 0
        expiration_date = str(result_whois['expiration_date'][0])
        formated_date = " ".join(expiration_date.split()[:1])
        d1 = datetime.datetime.strptime(formated_date, "%Y-%m-%d")
        d2 = datetime.datetime.now()
        dayz = abs((d1 - d2).days)
        if(dayz <=365):
            return -1
        else:
            return 1
    except Exception:
        return 0

def check_favicon(url):
    icons = favicon.get(url)
    icon = icons[0]
    icondomain = urlparse(icon.url).netloc
    websitedomain = urlparse(url).netloc
    if(icondomain == websitedomain):
        return 1
    else:
        return -1

def check_port_no(url):
    parse = urlparse(url)
    if(parse.port):
        if(parse.port in [21,22,23,80,443,445,1433,1521,3306,3389]):
            location = (url,o.port)
            a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result_of_check = a_socket.connect_ex(location)
            if result_of_check == 0:
                return 1
            else:
                return -1
        else:
            return -1
    else:
        return 1

def verify_domain(url):
    domain = urlparse(url).netloc
    if("https"in domain):
        return 1
    else:
        return -1

def request_url(url):
    
    response = requests.get(url)
    soup = BeautifulSoup(response.text,"html.parser")
    try:
        img_tags = soup.find_all("img")
        urls = [img['src'] for img in img_tags]
        website_domain = urlparse(url).netloc
        count =0 
        total = len(urls)
        for i in urls:
            img_domains = urlparse(i).netloc
            if(website_domain != img_domains):
                count+=1
        percent = (count/total) *100.0
        if(percent <22):
            return -1
        elif (percent>=22 and percent <61):
            return 0
        else:
            return 1
    except:
        return 0

def anchor_url(url):
    
    response = requests.get(url)
    soup = BeautifulSoup(response.text,"html.parser")
    img_tags = soup.find_all("a")
    try:
        urls = [img['href'] for img in img_tags]
        website_domain = urlparse(url).netloc
        count =0 
        total = len(urls)
        for i in urls:
            try:
                response = requests.get(url)
                img_domains = urlparse(i).netloc
                if(website_domain != img_domains):
                    count+=1
            except requests.ConnectionError as Exception:
                continue
        percent = (count/total) *100.0
        if(percent <31):
            return -1
        elif (percent>=31 and percent <67):
            return 0
        else:
            return 1
    except :
        return 0

def check_tags(url):

    response = requests.get(url)
    soup = BeautifulSoup(response.text,"html.parser")
    script_tags = soup.find_all("link")
    urls = [script['href'] for script in script_tags]
    website_domain = urlparse(url).netloc
    count =0 
    total = len(urls)
    for i in urls:
        try:
            response = requests.get(url)
            img_domains = urlparse(i).netloc
            if(website_domain != img_domains):
                count+=1
        except requests.ConnectionError as Exception:
            continue
    try:
        percent = (count/total) *100.0
    except:
        return 1
    if(percent <17):
        return 1
    elif (percent>=17 and percent <81):
        return 0
    else:
        return -1
    
def count_redirects(url):
    try:
        response = requests.get(url, timeout=3)
        if response.history:
            num= len(response.history)
            if(num<=1):
                return 1
            elif(num>=2 and num<4):
                return 0
            else:
                return -1
        else:
            return 1        
    except Exception:
        return 0

def right_click(url):
    PATH="D:\Downloads\Selenium\chromedriver.exe"

    driver = webdriver.Chrome(PATH)
    try:
        driver.get(url)
    except Exception:
        driver.close()
        return -1
    driver.maximize_window()
    source = driver.find_element_by_tag_name("div")
    action = ActionChains(driver)
    try:
        action.context_click(source).perform()
        driver.close()
        return 1
    except Exception:
        driver.close()
        return -1

def iframe_url(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text,"html.parser")
    iframe_tags = soup.find_all("iframe")
    if(len(iframe_tags)==0):
        return -1
    else:
        return 1
def domain_age(url):
    details = whois.whois(url)
    createdate=details.creation_date
    today=datetime.datetime.today()
    day=today.day-createdate.day
    month=today.month-createdate.month
    year=today.year-createdate.year
    age=(year*365)+(month*30)+day
    age=age/365
    if(age>=0.5):
        return 1
    else:
        return -1

def is_valid_domain(site_name):
    if validators.domain(site_name):
        return -1
    else:
        return 1

def alexa_rank(url):
    alexa_base_url = 'https://alexa.com/siteinfo/'
    site_name = url
    site_name.lower()
    if not is_valid_domain(site_name):
        print("Not a valid domain format ".format(site_name))
        print("Valid Top Level Domain looks like 'xyz.org' or 'www.xyz.org' ")
        exit(0)
    url_for_rank = alexa_base_url + site_name
    page = requests.get(url_for_rank)
    soup = BeautifulSoup(page.content, 'html.parser')
    global_rank = soup.select('.rank-global .data')
    try:
        match = re.search(r'[\d,]+', global_rank[0].text.strip())
        if(match.group()<100000):
            return 1
        elif(match.group()>100000):
            return 0
        else:
            return -1
    except:
        return -1




url = 	"https://linkaccessverification.weebly.com/"
# url = "https://www.facebook.com"
res = start_url(url)

print ("Extracting features and preapring array:")

data = []

#having ip address
data.append(valid_ip(res["host"]))

#Url length
data.append(length(url))

#shortening services
data.append(check_shortener(res))

#having @
data.append(check_at_symbol(url))

#double slash redirect
data.append(check_double_slash(url))

#prefix suffix
data.append(check_domain_dash(url))

#having sub domain
data.append(check_tld(url))

#SSL Final state
data.append(find_SSL(url))

#Domain registeration
data.append(expiration_date_register(res))

#favicon
data.append(check_favicon(url))

#port 
data.append(check_port_no(url))

#https token
data.append(verify_domain(url))

#request url
data.append(request_url(url))

#url of anchor
data.append(anchor_url(url))

#links inside tags
data.append(check_tags(url))

#SFH
data.append(-1)

#Submitting to email
data.append(-1)

#abnormal URL
data.append(-1)

#count redirects
data.append(count_redirects(url))

#on mouse over
data.append(-1)

#right click disabled
data.append(right_click(url))

#popupwindow
data.append(-1)

#iframe
data.append(iframe_url(url))

#age of domain
data.append(domain_age(url))

#DNS record
data.append(is_valid_domain(url))

#web traffic
data.append(1)

#alexa page rank
data.append(alexa_rank(url))

#google page rank
data.append(-1)

#links pointing to page
data.append(-1)

#statistical analysis
data.append(1)

print("the attribute array generated is \n",data)

#random forest algorithm

df = pd.read_csv("D:\\Codes\\Sem 7\\PMMS\\Dataset\\Training_Dataset.csv")

attributes = df.iloc[:,0:30].values
result = df.Result

attributes_train,attributes_test,result_train,result_test = train_test_split(attributes,result,test_size=0.5,random_state=0)

sc = StandardScaler()
attributes_train = sc.fit_transform(attributes_train)
attribites_test = sc.transform(attributes_test)

regressor = RandomForestRegressor(n_estimators=1000,random_state=42)
regressor.fit(attributes_train,result_train)
resul_pred = regressor.predict(attributes_test)

new_input = []
new_input.append(data)
array = np.array(new_input)
array.reshape(-1,1)
new_output = regressor.predict(array)
print(new_output)

if(new_output[0]<0):
    print ("The website is a phishing website")
elif (new_output[0]>0.9 and new_output<=1.0):
    print("Website is original")
else:
    print("The website appear to be suspicious")