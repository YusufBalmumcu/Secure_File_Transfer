import tkinter as tk
import threading
import socket
import os
import time # Zaman ölçümleri için
from datetime import datetime # Zaman damgaları için
from encryption import decrypt_aes_key, decrypt_file

HOST = '127.0.0.1'
PORT = 65432

# --- Ağ Performansı Ölçüm Fonksiyonları ---

def calculate_rtt(start_time):
    """Gidiş Dönüş Süresini (RTT) milisaniye cinsinden hesaplar."""
    end_time = time.time()
    rtt_ms = (end_time - start_time) * 1000
    return rtt_ms

def estimate_bandwidth(start_time, total_bytes):
    """Bant genişliğini Mbps (Saniyede Megabit) cinsinden tahmin eder."""
    end_time = time.time()
    duration_seconds = end_time - start_time
    if duration_seconds > 0:
        # Baytları bitlere, sonra megabitlere dönüştür
        bandwidth_mbps = (total_bytes * 8) / (duration_seconds * 1_000_000)
        return bandwidth_mbps
    return 0

# --- Sunucu Mantığı ---

def handle_received_data(data, client_address, protocol, start_time, log_func):
    try:
        # Performans metrikleri
        rtt = calculate_rtt(start_time)
        bandwidth = estimate_bandwidth(start_time, len(data))
        log_func(f"[{protocol}] Bağlantı: {client_address} | Gecikme (RTT): {rtt:.2f} ms | Bant Genişliği: {bandwidth:.2f} Mbps\n")

        encrypted_key = data[:256]
        encrypted_data = data[256:]

        aes_key = decrypt_aes_key(encrypted_key, "private_key.pem")
        plaintext = decrypt_file(encrypted_data, aes_key)

        os.makedirs("received_files", exist_ok=True)
        # Benzersiz dosya adları için zaman damgası ve istemci adresini kullan
        filename = f"received_files/received_data_{protocol}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{client_address[0]}.txt"
        with open(filename, "wb") as f:
            f.write(plaintext)

        log_func(f"[{protocol}] Dosya alındı ve '{filename}' olarak kaydedildi.\n")
    except Exception as e:
        log_func(f"[{protocol}] Hata: {e}\n")

def tcp_server(log_func):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        log_func(f"[TCP] Dinleniyor: {HOST}:{PORT}\n")
        while True:
            conn, addr = s.accept()
            with conn:
                log_func(f"[TCP] Bağlantı: {addr}\n")
                start_time = time.time() # RTT ve bant genişliği için başlangıç zamanı
                data = b""
                total_bytes_received = 0
                while True:
                    part = conn.recv(4096)
                    if not part:
                        break
                    data += part
                    total_bytes_received += len(part) # Baytları biriktir
                handle_received_data(data, addr, "TCP", start_time, log_func)

def udp_server(log_func):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((HOST, PORT))
        log_func(f"[UDP] Dinleniyor: {HOST}:{PORT}\n")
        while True:
            # UDP bağlantısızdır, bu yüzden RTT ölçümü daha karmaşıktır.
            # Sadece tek paketi almanın ne kadar sürdüğünü ölçeceğiz.
            start_time = time.time()
            data, addr = s.recvfrom(65535) # Maksimum UDP paket boyutu
            log_func(f"[UDP] Veri alındı: {addr}\n")
            handle_received_data(data, addr, "UDP", start_time, log_func)

def start_servers(log_widget):
    def log_func(message):
        log_widget.insert(tk.END, message)
        log_widget.see(tk.END)

    # Önceki günlükleri temizle
    log_widget.delete(1.0, tk.END)
    
    threading.Thread(target=tcp_server, args=(log_func,), daemon=True).start()
    threading.Thread(target=udp_server, args=(log_func,), daemon=True).start()
    log_func("Sunucu başlatıldı.\n")
    log_func("--- Ağ Performans Ölçümleri Etkinleştirildi ---\n")

# === Tkinter GUI ===
root = tk.Tk()
root.title("Güvenli Dosya Alıcı (Sunucu)")
root.geometry("600x400") # Biraz daha büyük pencere

log_box = tk.Text(root, height=20, width=70, font=("Arial", 10))
log_box.pack(pady=10)

start_button = tk.Button(root, text="Sunucuyu Başlat", command=lambda: start_servers(log_box), font=("Arial", 12), bg="#4CAF50", fg="white")
start_button.pack(pady=10)

root.mainloop()