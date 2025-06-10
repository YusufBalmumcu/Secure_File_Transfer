from tkinterdnd2 import DND_FILES, TkinterDnD
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from encryption import generate_aes_key, encrypt_file

def send_file_with_gui(file_path, host, port, protocol):
    """
    Belirtilen dosyayı seçilen protokol (TCP/UDP) üzerinden şifreleyerek gönderir.
    Dosya önce AES ile şifrelenir, ardından AES anahtarı RSA ile şifrelenir.
    """
    try:
        # Ortak anahtarı dosyadan oku
        with open("public_key.pem", "rb") as f:
            public_key = f.read()

        # Yeni bir AES anahtarı oluştur ve dosyayı bu anahtarla şifrele
        aes_key = generate_aes_key()
        encrypted_data = encrypt_file(file_path, aes_key)

        # AES anahtarını RSA ortak anahtarı ile şifrele
        rsa_key = RSA.import_key(public_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        # Şifrelenmiş AES anahtarını ve şifrelenmiş dosya verilerini birleştir
        data_to_send = encrypted_aes_key + encrypted_data

        # Seçilen protokole göre dosyayı gönder
        if protocol == "TCP":
            # TCP soketi oluştur ve sunucuya bağlan
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((host, int(port)))
                s.sendall(data_to_send) # Tüm veriyi gönder
        elif protocol == "UDP":
            # UDP soketi oluştur ve veriyi sunucuya gönder
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(data_to_send, (host, int(port)))
        else:
            # Geçersiz protokol seçimi hatası
            raise ValueError("Geçersiz protokol seçimi.")

        # Başarılı gönderme mesajı göster
        messagebox.showinfo("Başarılı", f"Dosya {protocol} ile gönderildi.")
    except Exception as e:
        # Herhangi bir hata durumunda hata mesajı göster
        messagebox.showerror("Hata", str(e))

def select_file():
    """Kullanıcının dosya seçmesini sağlayan iletişim kutusunu açar."""
    file_path = filedialog.askopenfilename()
    if file_path:
        update_selected_file(file_path)

def update_selected_file(file_path):
    """Seçilen dosya yolunu GUI'de günceller ve 'Gönder' butonunu etkinleştirir."""
    file_label.config(text=f"Seçilen Dosya:\n{file_path}")
    send_button.config(state="normal") # Dosya seçildiyse gönder butonunu etkinleştir
    send_button.file_path = file_path # Dosya yolunu butona ata

def send_selected_file():
    """GUI'deki alanlardan bilgileri alarak seçilen dosyayı gönderme işlemini başlatır."""
    file_path = getattr(send_button, "file_path", None) # Butona atanmış dosya yolunu al
    host = host_entry.get()
    port = port_entry.get()
    protocol = protocol_var.get()
    
    # Tüm alanların dolu olup olmadığını kontrol et
    if file_path and host and port and protocol:
        send_file_with_gui(file_path, host, port, protocol)
    else:
        messagebox.showwarning("Uyarı", "Lütfen tüm alanları doldurunuz.")

def on_drop(event):
    """Sürükle bırak olayı tetiklendiğinde dosya yolunu işler."""
    # Sürüklenen dosya yolunu al ve '{ }' karakterlerinden temizle
    file_path = event.data.strip('{}')
    update_selected_file(file_path)

# --- GUI Başlatma ---
root = TkinterDnD.Tk() # TkinterDnD sınıfını kullanarak ana pencereyi oluştur
root.title("Güvenli Dosya Gönderimi") # Pencere başlığını ayarla
root.geometry("450x420") # Pencere boyutunu ayarla

# HOST giriş alanı
tk.Label(root, text="HOST (IP):").pack()
host_entry = tk.Entry(root)
host_entry.insert(0, "127.0.0.1") # Varsayılan HOST IP'si
host_entry.pack(pady=5)

# PORT giriş alanı
tk.Label(root, text="PORT:").pack()
port_entry = tk.Entry(root)
port_entry.insert(0, "65432") # Varsayılan PORT
port_entry.pack(pady=5)

# PROTOKOL açılır menüsü
tk.Label(root, text="Protokol Seçimi:").pack()
protocol_var = tk.StringVar()
protocol_dropdown = ttk.Combobox(root, textvariable=protocol_var, state="readonly")
protocol_dropdown["values"] = ("TCP", "UDP") # Seçenekleri belirle
protocol_dropdown.current(0)  # Varsayılan olarak TCP'yi seç
protocol_dropdown.pack(pady=5)

# Dosya Seçme Butonu
select_button = tk.Button(root, text="Dosya Seç", command=select_file)
select_button.pack(pady=10)

# Drag & Drop (Sürükle ve Bırak) Alanı
file_label = tk.Label(root, text="Henüz dosya seçilmedi.", width=50, height=4, bg="#f0f0f0", relief="groove")
file_label.pack(pady=10)
file_label.drop_target_register(DND_FILES) # Dosyaların bu alana sürüklenmesine izin ver
file_label.dnd_bind('<<Drop>>', on_drop) # Sürükle bırak olayı için fonksiyonu bağla

# Gönder Butonu
send_button = tk.Button(root, text="Dosyayı Gönder", command=send_selected_file, state="disabled") # Başlangıçta pasif
send_button.pack(pady=10)

# Bilgilendirme metni
drag_info = tk.Label(root, text="Dosya sürükleyip yukarı bırakabilirsiniz.", fg="gray")
drag_info.pack(pady=5)

root.mainloop() # Tkinter olay döngüsünü başlat