# Wi-Fi Password Cracker

This is a Python-based Wi-Fi password cracking tool that uses a dictionary-based approach to attempt to crack the password of WPA2-PSK secured Wi-Fi networks. It uses the `pywifi` library for Wi-Fi management, `tkinter` for the GUI interface, and `pyperclip` to copy cracked passwords to the clipboard. 


![wifibruter](https://github.com/user-attachments/assets/a844647f-57ab-46d0-a414-caf979bf91fb)

## Features

- **Wi-Fi Network Scanning**: Scans and displays a list of available Wi-Fi networks.
- **Crack WPA2-PSK Passwords**: Attempts to crack WPA2-PSK protected networks using a wordlist.
- **Progress Bar**: Displays the progress of the cracking process with a visual progress bar.
- **Console Output**: Shows detailed logs of the cracking attempt in a console-like text area.
- **Clipboard Support**: Allows the user to copy the cracked password to the clipboard.
- **Custom Wordlist**: Users can use a custom password list to try different password combinations.


## Requirements

- Python 3.x
- **Libraries**:
  - `pywifi` (for Wi-Fi network management)
  - `pyperclip` (for clipboard functionality)
  - `tkinter` (for GUI)
  - `threading` (for background operations)



You can install the necessary Python libraries with the following commands:

```bash
pip install pywifi pyperclip


