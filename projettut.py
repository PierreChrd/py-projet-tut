import nmap, socket, json, pyfiglet
from datetime import datetime

class Network(object):
    def __init__(self):
        print(pyfiglet.figlet_format("PROJET TUT.PY"))
        self.ip = input(f"Entrer une adresse IP (l'adresse IP de cette machine est par défaut :\n{socket.gethostbyname(socket.gethostname())}, pour la selectionner appuyez sur ENTRER).\n>")
        self.hosts = []
        self.nm = nmap.PortScanner()

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
            print("Hote\t{}".format(host))
            self.hosts.append(host)
        print("=" * 50)
        print(self.hosts)
    
    def nmap_scan(self, host):
        print(f"Début du scan pour :\t{host}.")
        scan_result = self.nm.scan(hosts = host, arguments = '-sV --script="vuln and safe"')
        # scan_result = self.nm.scan(hosts = host, arguments = '-sV --script vuln')
        # scan_result = self.nm.scan(hosts = host, arguments = '-sV --script=vulscan/vulscan.nse')
        print(scan_result)

        with open(f"scan/{host}.json", "w", encoding= "utf-8") as f:
            f.write(json.dumps(scan_result, indent=4, sort_keys=True))

    def projet_tut(self):
        self.network_scanner()
        # self.nmap_scan("192.168.56.1")
        for i in range(len(self.hosts)):
            self.nmap_scan(self.hosts[i])

if __name__ == "__main__":
    Nscan = Network()
    Nscan.projet_tut()