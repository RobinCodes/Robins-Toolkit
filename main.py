import requests
import ctypes
import os
import colorama
import sublist3r
import time
import nmap
from bs4 import BeautifulSoup
import re

version = "1.0" # current version

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

#logo
def logo():
    print(colorama.Fore.BLUE + '''
   __       _     _             _____            _ _    _ _   
  /__\ ___ | |__ (_)_ __  ___  /__   \___   ___ | | | _(_) |_ 
 / \/// _ \| '_ \| | '_ \/ __|   / /\/ _ \ / _ \| | |/ / | __|
/ _  \ (_) | |_) | | | | \__ \  / / | (_) | (_) | |   <| | |_ 
\/ \_/\___/|_.__/|_|_| |_|___/  \/   \___/ \___/|_|_|\_\_|\__|''')

def help():
    clear_screen()
    logo()
    print("\nWelcome to RobinToolkit\n\nCurrently this tool only has basic features e.g. subdomain enumaration, port scanning and etc, however, much more is coming soon.\n")
    print("Github: https://github.com/RobinCodes\n")

    input("\nPress any button to continue....")
    main()

#auto updater script
def update():
    url = 'https://raw.githubusercontent.com/RobinCodes/Robins-Toolkit/refs/heads/main/version.txt' 
    
    try:
        r = requests.get(url)
        r.raise_for_status()  # error for bad response
        content = r.text.strip()  

        if content == version:
            main()  # go to main if version is up to date
        else:
            print(f"Update available!\nCurrent version: {version}, New version: {content}\nDownload newest version here: https://github.com/RobinCodes/Robins-Toolkit\n")
            input("Press any button to continue....")
            main()
    except requests.RequestException as e:
        print(f"An error occurred while checking for updates: {e}\n")
        input("\nPress any button to continue....")
        main()

def web_vunerability_finder():
    clear_screen()
    logo()

    host = input("\nWebsite: ")
    print("")
    time.sleep(2)
    #website to ip so it is compatible with internetdb api
    response = requests.get(f'https://dns.google/resolve?name={host}&type=A')
    data = response.json()
    
    if 'Answer' in data:
        website_ip = data['Answer'][0]['data']
    else:
        print("Error no IP address found")

    vuln = requests.get(f"https://internetdb.shodan.io/{website_ip}")

    if vuln.status_code == 200:
        data = vuln.json()
        for key, value in data.items():
            print(f"{key}: {value}")
    else:
        print("")
        print({"status": "fail", "message": "Unable to retrieve data"})
        print("")

    input("\nPress any button to continue....")
    main()

def subdomain_finder():
    clear_screen()
    logo()
    print("\n(An error pops up when running this script, please ignore it)")
    host = input("\nWebsite: ")
    print("")
    #subdomain finder
    subdomains = sublist3r.main(host, 40, savefile=None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
    
    #prints all the subdomains
    clear_screen()
    logo()
    print("")
    print(subdomains)

    input("\nPress any button to continue....")
    main()

def ip_lookup():
    clear_screen()
    logo()

    ip_address = input("\nIP: ")
    print("")

    # a bunch of IP API's to get lots of information just of an IP address 
    response_locate = requests.get(f"http://ip-api.com/json/{ip_address}")
    response_whois = requests.get(f"https://api.domaintools.com/v1/domaintools.com/whois/{ip_address}")
    
    if response_locate.status_code == 200:
        print("IP Geo-Location Info\n")
        data1 = response_locate.json()
        for key, value in data1.items():
            print(f"{key}: {value}")
    else:
        print("")
        print({"status": "fail", "message": "Unable to retrieve data"})

    if response_whois.status_code == 200:
        print("\nIP WHOIS Info\n")
        data2 = response_whois.json()
        for key, value in data2.items():
            print(f"{key}: {value}")
    else:
        print("")
        print({"status": "fail", "message": "Unable to retrieve data"})

    input("\nPress any button to continue....")
    main()

def leak_search():
    clear_screen()
    logo()

    host = input("\nEmail/Username: ")
    print("")

    leaks1 = requests.get(f"https://psbdmp.ws/api/search/{host}")
    leaks2 = requests.get(f"https://psbdmp.ws/api/search/{host}")
    leaks3 = requests.get(f"https://api.xposedornot.com/v1/check-email/{host}")

    if leaks1.status_code == 200:
        data1 = leaks1
        print(data1)
    else:
        print("")
        print({"status": "fail", "message": "Unable to retrieve data"})

    if leaks2.status_code == 200:
        data2 = leaks2.json()
        print(data2)
        print("")
    else:
        print("")
        print({"status": "fail", "message": "Unable to retrieve data"})

    if leaks3.status_code == 200:
        data3 = leaks3.json()
        print(data3)
        print("")
        print("")
    else:
        print("")
        print({"status": "fail", "message": "Unable to retrieve data"})

    input("\nPress any button to continue....")
    main()

def port_scanner():
    clear_screen()  
    logo()  
    
    target = input("\nWebsite: ")
    commands = input("Input nmap command to use (default: -sS -sV -O -A -p 1-1000): ").strip() or "-sS -sV -O -A -p 1-1000"

    print("\nPlease wait for the scan to finish (this may take a while).....")

    scanner = nmap.PortScanner()

    #starts the scanner with specified options
    scanner.scan(target, arguments=commands)

    clear_screen()
    logo()

    print("\nNmap Scan Information Below\n")

    # Prints the scan 
    for host in scanner.all_hosts():
        print("Host: ", host)
        print("State: ", scanner[host].state())
        for proto in scanner[host].all_protocols():
            print("Protocol: ", proto)
            ports = scanner[host][proto].keys()
            for port in ports:
                print("Port: ", port, "State: ", scanner[host][proto][port]['state'])
    
    input("\nPress any button to continue....")
    main()  

def google_dorks():
    clear_screen()
    logo()

    dorks = input("\nWebsite: ")

    print(f"\nsite:{dorks} inurl admin | https://www.google.com/search?q=site%3A{dorks}+inurl+admin")
    print(f"site:{dorks} inurl /admin/index.php | https://www.google.com/search?q=site%3A{dorks}+inurl+%2Fadmin%2Findex.php")
    print(f"site:{dorks} inurl index.php | https://www.google.com/search?q=site%3A{dorks}+inurl+index.php")

    input("\nPress any button to continue....")
    main()

def xss():
    clear_screen()
    logo()

    website = input("\nWebsite: ")
    xss_file_path = "xss.txt" # file path with all the xss strings   

    try:
        response = requests.get(website)
        response.raise_for_status()  # Check for errors
    except requests.RequestException as e:
        print(f"Error fetching the URL: {e}")
        input("\nPress any button to continue....")
        main()

    # Parse the page 
    soup = BeautifulSoup(response.content, 'html.parser')

    # gets all the input box's on the page
    input_boxes = soup.find_all('input', type='text')
    
    if not input_boxes:
        print("\nNo text input boxes found on the page.")
        input("\nPress any button to continue....")
        main()

    with open(xss_file_path, 'r', encoding='utf-8') as file:
        xss_list = file.readlines()

    #loop
    for input_box in input_boxes:
        input_name = input_box.get('name', 'Unnamed Input')
        print(f"\nTesting input box for XSS Vulnerabilities: {input_name}")
        
        for xss_data in xss_list:
            xss_data = xss_data.strip()  
            if not xss_data:
                continue  # Skip emtpy stuff

            post_data = {input_name: xss_data}

            action_url = website

            try:
                post_response = requests.post(action_url, data=post_data)
                alert_pattern = re.compile(r'alert\((.*?)\);', re.DOTALL)
                match = alert_pattern.search(post_response.text)

                if match:
                    alert_message = match.group(1).strip("'\"")  
                    print(f"\nAlert box detected, however, not vulnerable.")
                    
                    if xss_data in alert_message:
                        print(f"Working XSS String: {xss_data}")
                        input("\nPress any button to continue....")
                        main()   
                else:
                    print("No alert box popped up.")  # No alert box found
                    input("\nPress any button to continue....")
                    main()
            except requests.RequestException as e:
                print(f"Error during POST request: {e}") # gets errors
                input("\nPress any button to continue....")
                main()

    input("\nPress any button to continue....")
    main()

def web_scraper():
    clear_screen()
    logo()
    website = input("\nWebsite (https://example.com): ")

    req = requests.get(f"{website}")

    soup = BeautifulSoup(req.content, "html.parser")

    print("")
    print(soup.prettify())

    input("Press any button to continue....")
    main()  

def main():
    clear_screen()

    logo()

    print('''
╔════════════════════════════════════════════════════════════════╗
    Recon               Pentesting               Data Search                  
        
    1. IP              5. Subdomain finder      8. Leak Check  
    2. Port Scanner    6. Web Vunerabilty 
    3. Google Dorks    7. XSS Finder [BETA]
    4. Web Scraper

╚════════════════════════════════════════════════════════════════╝
''')

    option = input("Choose an option (H): ")

    if option == "1":
        ip_lookup()

    else:
        if option == "2":
            port_scanner()

        else:
            if option == "3":
                google_dorks()

            else:
                if option == "4":
                    web_scraper()

                else:
                    if option == "5":
                        subdomain_finder()
        
                    else:
                        if option == "6":
                            web_vunerability_finder()

                        else:
                            if option == "7":
                                xss()

                            else:
                                if option == "8":
                                    leak_search()

                                else:
                                    if option == "H" or "h" or "help" or "Help":
                                        help()

                                    else:
                                        main() # if random data is entered it goes back to main()


if __name__ == "__main__":
    clear_screen()
    ctypes.windll.kernel32.SetConsoleTitleW("RobinsToolkit | Made By: Robin") # sets window name
    update()
    main()
