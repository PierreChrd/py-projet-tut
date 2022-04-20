import nmap, socket, json, pyfiglet
from pycvesearch import CVESearch
from datetime import datetime

class Network(object):
    def __init__(self):
        print(pyfiglet.figlet_format("PROJET TUT.PY"))
        self.ip = input(f"Entrer une adresse IP (l'adresse IP de cette machine est par défaut :\n{socket.gethostbyname(socket.gethostname())}, pour la selectionner appuyez sur ENTRER).\n>")
        self.hosts = []
        self.nm = nmap.PortScanner()
        self.cve = CVESearch()

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
            print("Hôte\t{}".format(host))
            self.hosts.append(host)
        print("=" * 50)
        # print(self.hosts)
    
    def nmap_scan(self, host):
        print(f"\nDébut du scan Nmap pour :\t{host}.")
        scan_result = self.nm.scan(hosts = host, arguments = '-sV --script="vuln and safe"')
        # scan_result = self.nm.scan(hosts = host, arguments = '-sV --script vuln')
        # scan_result = self.nm.scan(hosts = host, arguments = '-sV --script=vulscan/vulscan.nse')
        # print(scan_result)

        with open(f"scan/{host}.json", "w", encoding= "utf-8") as f:
            f.write(json.dumps(scan_result, indent=4, sort_keys=True))
    
    def read_json_scan(self, ip):
        with open(f"scan/{ip}.json", "r", encoding= "utf-8") as f:
            arr = []
            res = json.loads(f.read())
            # print(res['scan']['192.168.56.0']['tcp'])
            for port in res['scan'][ip]['tcp']:
                print("=" * 50)
                print("PORT: {}".format(port))
                print("| NAME: {}".format(res['scan'][ip]['tcp'][port]['name']))
                print("| PRODUCT: {}".format(res['scan'][ip]['tcp'][port]['product']))
                try:
                    print("| SCRIPT:")
                    for script_statment in res['scan'][ip]['tcp'][port]['script']:
                        print("| | {}: ".format(script_statment.upper()) + res['scan'][ip]['tcp'][port]['script'][script_statment])
                        arr.append(res['scan'][ip]['tcp'][port]['script'][script_statment])
                except:
                    pass
                print("| STATE: {}".format(res['scan'][ip]['tcp'][port]['state']))
                print("|_VERSION: {}".format(res['scan'][ip]['tcp'][port]['version']))

    def cve_finder(self):
        cve_entry = str(input("\nSaisissez un code CVE pour votre recherche:\n>"))
        cve_result = self.cve.id(cve_entry)

        with open(f"cve/{cve_entry}.json", "w", encoding= "utf-8") as f:
            f.write(json.dumps(cve_result, indent=4, sort_keys=True))

    def projet_tut(self):
        self.network_scanner()
        for i in range(len(self.hosts)):
            self.nmap_scan(self.hosts[i])
            self.read_json_scan(self.hosts[i])
            self.cve_finder()


if __name__ == "__main__":
    Nscan = Network()
    Nscan.projet_tut()
