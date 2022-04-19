import json

ip = "192.168.56.1"

with open(f"{ip}.json", "r", encoding= "utf-8") as f:
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
        except:
            pass
        print("| STATE: {}".format(res['scan'][ip]['tcp'][port]['state']))
        print("|_VERSION: {}".format(res['scan'][ip]['tcp'][port]['version']))

        
        # cve_result = res['scan'][ip]['tcp'][port]['script']['http-slowloris-check']
        # print("\n" + cve_result)
