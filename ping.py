import os
import subprocess
import threading
import time
from scapy.all import sniff, IP
import pygame

# --- Constants ---
ROBLOX_IP_PREFIXES = ["128.116.", "192.225."]  # Known Roblox IP prefixes
ROBLOX_SERVERS = set()  # Detected Roblox servers will be stored here
DNS_SERVERS = ["1.1.1.1", "8.8.8.8"]  # Cloudflare and Google DNS

# --- Functions ---

# Chroma Banner Display
def display_chroma_banner():
    print("[INFO] Starting Chroma Banner...")
    pygame.init()
    screen_width, screen_height = 800, 200
    screen = pygame.display.set_mode((screen_width, screen_height))
    pygame.display.set_caption("AS Boost - Roblox Ping Booster")

    font = pygame.font.SysFont("Arial", 48)
    running = True
    colors = [(255, 0, 0), (0, 255, 0), (0, 0, 255)]  # Red, Green, Blue
    color_index = 0

    while running:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                running = False

        # Fill screen with current color
        screen.fill(colors[color_index])

        # Render "AS Boost" text
        text_surface = font.render("AS Boost - Optimizing Roblox", True, (255, 255, 255))
        screen.blit(text_surface, ((screen_width - text_surface.get_width()) // 2,
                                   (screen_height - text_surface.get_height()) // 2))

        pygame.display.flip()
        color_index = (color_index + 1) % len(colors)
        time.sleep(0.5)

    pygame.quit()

# Optimize DNS settings for low latency
def optimize_dns():
    print("[INFO] Configuring DNS for low latency...")
    try:
        resolv_conf = "/etc/resolv.conf"
        with open(resolv_conf, "w") as file:
            for dns in DNS_SERVERS:
                file.write(f"nameserver {dns}\n")
        print("[INFO] DNS successfully optimized.")
    except Exception as e:
        print(f"[ERROR] Failed to configure DNS: {e}")

# Enable packet prioritization for better network performance
def enable_packet_prioritization():
    print("[INFO] Enabling packet prioritization...")
    try:
        os.system("sysctl -w net.ipv4.tcp_low_latency=1")
        os.system("tc qdisc add dev eth0 root fq")  # Add Fair Queuing
        print("[INFO] Packet prioritization enabled.")
    except Exception as e:
        print(f"[ERROR] Failed to enable packet prioritization: {e}")

# Detect Roblox servers by monitoring live network traffic
def detect_roblox_servers():
    print("[INFO] Detecting Roblox servers...")
    def packet_callback(packet):
        if IP in packet:
            dest_ip = packet[IP].dst
            for prefix in ROBLOX_IP_PREFIXES:
                if dest_ip.startswith(prefix):
                    ROBLOX_SERVERS.add(dest_ip)
                    print(f"[INFO] Detected Roblox server: {dest_ip}")

    try:
        sniff(filter="ip", prn=packet_callback, timeout=60)  # Monitor traffic for 60 seconds
    except Exception as e:
        print(f"[ERROR] Failed to sniff network traffic: {e}")

# Optimize routing for Roblox servers
def optimize_routing():
    print("[INFO] Optimizing routing for detected Roblox servers...")
    for server in ROBLOX_SERVERS:
        try:
            os.system(f"ip route add {server} via 192.168.1.1")  # Replace with your router's IP
            print(f"[INFO] Routing optimized for Roblox server: {server}")
        except Exception as e:
            print(f"[ERROR] Failed to optimize routing for {server}: {e}")

# Ping Roblox servers to measure latency
def ping_server(server):
    try:
        print(f"[INFO] Pinging Roblox server: {server}")
        response = subprocess.run(["ping", "-c", "4", server], stdout=subprocess.PIPE, text=True)
        print(response.stdout)
    except Exception as e:
        print(f"[ERROR] Failed to ping server {server}: {e}")

# --- Background Task ---
def run_in_background():
    print("[INFO] Running Roblox Ping Booster in the background...")
    threading.Thread(target=display_chroma_banner, daemon=True).start()
    optimize_dns()
    enable_packet_prioritization()
    detect_roblox_servers()
    if ROBLOX_SERVERS:
        optimize_routing()
        for server in ROBLOX_SERVERS:
            threading.Thread(target=ping_server, args=(server,)).start()
    else:
        print("[WARNING] No Roblox servers detected. Make sure Roblox is running.")

# --- Main Program ---
if __name__ == "__main__":
    print("[INFO] Starting Roblox Ping Booster...")
    run_in_background()
