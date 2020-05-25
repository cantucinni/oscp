#!/usr/bin/python3

import os

def DoMyShit():

    with open("ips.txt") as f:
        for a in f.readlines():
            ip = a.strip()

            print("Trying {0}...".format(ip))

            try:

                qscan = os.path.join(ip, "nmap_quick.txt")

                if not os.path.exists(ip):
                    print("{0} does not yet exist. Making dirs for it.".format(ip))
                    os.makedirs(ip)


                if os.path.isfile(qscan):
                    if os.stat(qscan).st_size > 5:
                        print("Scan done on this machine already. {0}".format(ip))
                        continue

                    else:
                        print("Scan might have been done on this macihe, but is incomplete.")

                #let's run our scanning!

                print("Scanning...")
                os.system("nmap -sV -O {0} -o {1}".format(ip, qscan))

            except:
                pass

            
                


    pass


if __name__ == '__main__':
    DoMyShit()