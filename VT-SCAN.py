import requests
import base64


class colors:
    Blue = '\033[94m'
    Red = '\033[91m'
    Yellow = '\033[93m'
    Green = '\033[92m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
def Scan_IP():                    #Scan IP
    IP = input(f"{colors.Yellow}Enter IP For Scan: {colors.END}")
    URL = 'https://www.virustotal.com/api/v3/ip_addresses/'
    headers = {'x-apikey':apikey} 
    res = requests.get(URL + IP.strip(), headers=headers)        #take it ip & send to VTotal by api
    status =res.status_code                             #show status code
    value = res.json()
    if status == 200:
        if value['data']['attributes']['last_analysis_stats']['malicious'] > 0:
            print(f"{colors.Red}>>> This Is IP Malicious ( {IP} ).{colors.END}\n\nThank You For Use VT-SCAN")
        else:
            print(f">>> This is IP Clean ({IP}).{colors.Blue}\n\nThank You For Use VT-SCAN")
    else:
        print(f"""Try Again ):\n\n{colors.Yellow}{colors.UNDERLINE}Error Code: {value['error']['code']}\nError Description: {value['error']['message']}{colors.END}""")
def Scan_URL():                   #Scan URL
    url_path = input(f"{colors.Yellow}Enter URL For Scan: {colors.END}")
    URL = 'https://www.virustotal.com/api/v3/urls/'
    headers = {'x-apikey':apikey}
    url_id = base64.urlsafe_b64encode(url_path.encode()).decode().strip("=")
    res = requests.get(URL + url_id.strip(), headers=headers)
    value = res.json()
    status = res.status_code
    if status == 200:
        if value['data']['attributes']['last_analysis_stats']['malicious'] > 0:
            print(f"{colors.Red}>>> This is Malicious ({url_path}).{colors.END}\n\nThank You For Use VT-SCAN.")
        else:
            print(f">>> This is Clean ({url_path}).\n\nThank You For Use VT-SCAN.")
    else:
        print(f"""Try Again ):\n\n{colors.Yellow}{colors.UNDERLINE}Error Code: {value['error']['code']}\nError Description: {value['error']['message']}{colors.END}""")
def Scan_Domain():                #Scan Domain
    Domain = input("Enter Domain For Scan: ")
    URL = 'https://www.virustotal.com/api/v3/domains/'
    headers = {'x-apikey':apikey}
    res = requests.get(URL + Domain.strip(), headers=headers)
    status = res.status_code
    value = res.json() 
    if status == 200:
        if value['data']['attributes']['last_analysis_stats']['malicious'] > 0:
            print(f"{colors.Red}>>> This is Malicious ({Domain}).{colors.END}\n\nThank You For Use VT-SCAN")
        else:
            print(f">>> This is Clean ({Domain}).\n\nThank You For Use VT-SCAN")
    else:
        print(f"""Try Again ):\n\n{colors.Yellow}{colors.UNDERLINE}Error Code: {value['error']['code']}\nError Description: {value['error']['message']}{colors.END}""")
def Scan_Hash():                  #Scan Hash
    print(f"{colors.Green}* SHA-256, SHA-1 or MD5 Identifying The File. {colors.END}")
    Hash = input(f"{colors.Yellow}Enter Hash For Scan: {colors.END}")
    URL = 'https://www.virustotal.com/api/v3/files/'
    headers = {'x-apikey':apikey}
    res = requests.get(URL + Hash.strip(), headers=headers)
    status = res.status_code
    value = res.json()
    if status == 200:
        if value['data']['attributes']['last_analysis_stats']['malicious'] > 0:
            print(f"{colors.Red}>>>This is Malicious({Hash}).{colors.END}\nThank You For Use VT-SCAN")
        else:
            print(f">>> This is Clean('{Hash}').\n\nThank You For Use VT-SCAN")
    else:
        print(f"""Try Again ):\n\n{colors.Yellow}{colors.UNDERLINE}Error Code: {value['error']['code']}\nError Description: {value['error']['message']}{colors.END}""")

print(f"""
    {colors.Blue}                                                                                                                                       
     ` `      . ., .   .,.  ` `   ``     ````  ``     `````          ``       ```    `  `     ``  ``   `                        
   .ohhho.  .ohy+-hyMRZER00hhh`        `:ssooshy`   -+ysooyy-     `yhh-     -shhy.   :yh+` /hhh+   `+hy:    
    `dMMo    +Mo -mo` sMMy `sm.        yMM-   sm` `yNN:   :m/     smMMd`     +MNMm-   yM`   mMMMs`  `My       
     :MMN`  .my   .   sMMy   .         hMMh:.  `  sMMs     `     /N-yMM+     +M+mMN/  yM    mhsMMh. `Ms        
      yMMs  hd`       sMMy      ----.  .smMMmh/`  NMM/          -N/ .NMN.    +M--dMNo yM    md +NMm- Ms          
      `NMN-+N.        sMMy     `ZER00    `-+dMMd` mMM+         `MR--ZER00    +M- .hMMsyM    md  :NMN:Ms         
       +MMdN/         sMMy      ````` `s-   `mMM. +MMh    `s-  hm.....mMM:   +M-  `sMMNM    md   -dMNMs       
        hMMo         -dMMd-           .Nm+::oNd/   /dNh/:/dN/-yMh.   .hMMm: .yMo`   +NMM   :NN-   .hMMs        
        `--          ..--..            .--::-.`     `.--:--.``.-.`   `.---. `.-.`    .-.   .--.    `.-`  MR-ZER00 
        {colors.END} 
    {colors.Red}** Welcome To VT-SCAN (viurs total api)\n
    {colors.Green}** In order to use the API you must sign up https://www.virustotal.com/gui/sign-in.
    you will find your personal API key in your personal settings section.
    This key is all you need to use the VirusTotal API.{colors.Blue}
        If You Faced With Errors Please Contact Me On Telegram https://t.me/OX0ZER0 .  """)

apikey = input(f"""{colors.Yellow}For use VT-Scan Enter your API: {colors.END}""")                               #input apikey
chose_number = int(input(f"""chose number frome the list:{colors.Blue}
    1- Scan IP
    2- Scan URL
    3- Scan Domian
    4- Scan Hash\n
{colors.Yellow}> Your Chose: {colors.END} """))

if chose_number == 1:
    Scan_IP()
elif chose_number == 2:
    Scan_URL()
elif chose_number == 3:
    Scan_Domain()
elif chose_number == 4:
    Scan_Hash()
else:
    print(f"{colors.Red}Pleas, Chose From that The List....    Try again.")