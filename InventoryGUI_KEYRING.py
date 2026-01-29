import sys
import subprocess
import os
import json
import threading
import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext, ttk
from datetime import datetime

# --- Auto-Install Requests & Keyring ---
def install_and_import(packages):
    for package in packages:
        try:
            __import__(package)
        except ImportError:
            print(f"Installing {package}...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            except subprocess.CalledProcessError:
                tk.messagebox.showerror("Error", f"Failed to install {package}.")
                sys.exit(1)

install_and_import(['requests', 'keyring'])
import requests
import keyring

class InventoryApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Inventory Manager")
        self.root.geometry("700x550")
        
        # --- Configuration ---
        self.app_name = "TDX_Inventory_Script" # Name for the Keychain Entry
        self.api_user = "UserServicesAssetAPI" # Account Name
        
        self.sandbox = False
        if self.sandbox:
            self.tdx_base = 'https://spidertechnet.richmond.edu/sbTDWebApi/'
        else:
            self.tdx_base = 'https://spidertechnet.richmond.edu/tdwebapi/'
            
        self.session = requests.Session()
        self.bearer_token = ""
        
        # Build the UI
        self.build_menu() # Added File Menu for clearing password
        self.build_ui()
        
        # Attempt Login immediately
        self.root.after(200, self.try_auto_login)

    def build_menu(self):
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Clear Saved Password", command=self.clear_credentials)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        self.root.config(menu=menubar)

    def build_ui(self):
        # --- Top Frame: Controls ---
        control_frame = ttk.LabelFrame(self.root, text="Jobs")
        control_frame.pack(fill="x", padx=10, pady=5)
        
        self.btn_inventory = ttk.Button(control_frame, text="Return to Inventory", command=self.open_inventory_window, state="disabled")
        self.btn_inventory.pack(side="left", padx=5, pady=10)
        
        self.btn_dispose = ttk.Button(control_frame, text="Dispose Asset", command=self.open_dispose_window, state="disabled")
        self.btn_dispose.pack(side="left", padx=5, pady=10)

        self.btn_retire = ttk.Button(control_frame, text="Retire Asset", command=self.open_retire_window, state="disabled")
        self.btn_retire.pack(side="left", padx=5, pady=10)

        # --- Status Bar ---
        self.lbl_status = ttk.Label(self.root, text="Status: Checking Credentials...", foreground="blue")
        self.lbl_status.pack(pady=5)

        # --- Bottom Frame: Logs ---
        log_frame = ttk.LabelFrame(self.root, text="Activity Log")
        log_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.log_area = scrolledtext.ScrolledText(log_frame, height=15, state='disabled', font=("Consolas", 10))
        self.log_area.pack(fill="both", expand=True, padx=5, pady=5)

    def log(self, message):
        self.log_area.config(state='normal')
        self.log_area.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n")
        self.log_area.see(tk.END)
        self.log_area.config(state='disabled')

    def set_connected(self, state=True):
        if state:
            self.lbl_status.config(text="Status: Connected to TeamDynamix", foreground="green")
            self.btn_inventory.config(state="normal")
            self.btn_dispose.config(state="normal")
            self.btn_retire.config(state="normal")
        else:
            self.lbl_status.config(text="Status: Not Logged In", foreground="red")
            self.btn_inventory.config(state="disabled")
            self.btn_dispose.config(state="disabled")
            self.btn_retire.config(state="disabled")

    # ==========================
    # AUTHENTICATION & KEYRING
    # ==========================
    def try_auto_login(self):
        """Checks OS Keychain for saved password"""
        saved_pass = keyring.get_password(self.app_name, self.api_user)
        
        if saved_pass:
            self.log("Found saved password in Keychain. Logging in...")
            # False = Do not save again, we just read it
            threading.Thread(target=self.authenticate, args=(saved_pass, False), daemon=True).start()
        else:
            self.log("No saved credentials found.")
            self.prompt_login()

    def prompt_login(self):
        self.set_connected(False)
        password = simpledialog.askstring("Login Required", 
                                          "Enter TDX API Password:\n(This will be saved securely to your Keychain)", 
                                          show='*')
        if not password:
            self.log("Login cancelled.")
            return

        # True = Save this password if login succeeds
        threading.Thread(target=self.authenticate, args=(password, True), daemon=True).start()

    def authenticate(self, password, save_on_success):
        self.log("Authenticating...")
        auth_url = f"{self.tdx_base}api/auth"
        payload = {'UserName': self.api_user, 'Password': password}
        
        try:
            response = self.session.post(auth_url, data=payload)
            response.raise_for_status()
            
            self.bearer_token = f"Bearer {response.text.strip().replace('"', '')}"
            self.session.headers.update({'Authorization': self.bearer_token})
            
            self.log("Authentication Successful.")
            self.root.after(0, lambda: self.set_connected(True))

            if save_on_success:
                try:
                    keyring.set_password(self.app_name, self.api_user, password)
                    self.log("Password saved securely to Keychain.")
                except Exception as k_err:
                    self.log(f"Warning: Could not save password: {k_err}")

        except Exception as e:
            self.log(f"Auth Error: {e}")
            self.root.after(0, lambda: self.set_connected(False))
            # Only prompt retry if we aren't in the middle of an auto-login loop
            if save_on_success: 
                messagebox.showerror("Login Failed", str(e))
            else:
                # If auto-login failed, the password might be changed. Clear it.
                self.log("Saved password failed. Clearing...")
                self.clear_credentials()
                self.root.after(0, self.prompt_login)

    def clear_credentials(self):
        try:
            keyring.delete_password(self.app_name, self.api_user)
            self.log("Credentials cleared from Keychain.")
            messagebox.showinfo("Success", "Saved password removed.")
        except keyring.errors.PasswordDeleteError:
            self.log("No credentials to clear.")

    # ==========================
    # HELPER FUNCTIONS
    # ==========================
    def remove_users(self, asset_id):
        self.log(f"Clearing users for Asset ID {asset_id}...")
        try:
            r = self.session.get(f"{self.tdx_base}api/1154/assets/{asset_id}/users")
            users = r.json()
            for user in users:
                uid = user['Value']
                self.session.delete(f"{self.tdx_base}api/1154/assets/{asset_id}/users/{uid}")
            self.log("Users cleared.")
        except Exception as e:
            self.log(f"Warning: Failed to clear users: {e}")

    def add_feed_comment(self, asset_id, comment):
        try:
            url = f"{self.tdx_base}api/1154/assets/{asset_id}/feed"
            self.session.post(url, data={'Comments': comment, 'IsPrivate': True})
        except:
            pass

    def update_attributes(self, record, attr_id, value):
        attributes = record.get('Attributes', [])
        found = False
        for attr in attributes:
            if attr['ID'] == attr_id:
                attr['Value'] = value
                found = True
                break
        if not found:
            attributes.append({'ID': attr_id, 'Value': value})
        return attributes

    def find_and_get_asset(self, serial):
        try:
            r = self.session.post(f"{self.tdx_base}api/1154/assets/search", json={'SerialLike': serial})
            results = r.json()
            if not results:
                self.log("Asset not found.")
                return None, None
            if len(results) > 1:
                self.log("Multiple assets found. Fix manually.")
                return None, None
            
            asset_id = results[0]['ID']
            self.log(f"Found Asset ID: {asset_id}")
            
            r_det = self.session.get(f"{self.tdx_base}api/1154/assets/{asset_id}")
            return asset_id, r_det.json()
        except Exception as e:
            self.log(f"API Error: {e}")
            return None, None

    def send_update(self, asset_id, payload):
        try:
            self.session.post(f"{self.tdx_base}api/1154/assets/{asset_id}", json=payload)
            self.log("Asset updated successfully.")
            return True
        except Exception as e:
            self.log(f"Update Failed: {e}")
            return False

    def create_input_window(self, title, callback, needs_tag=True, extra_fields=None):
        win = tk.Toplevel(self.root)
        win.title(title)
        
        # Adjust height based on fields
        rows = 2 + (1 if needs_tag else 0) + (len(extra_fields) if extra_fields else 0)
        win.geometry(f"400x{rows * 60 + 50}")
        
        entries = {}

        ttk.Label(win, text="Serial Number:").pack(pady=2)
        ent_serial = ttk.Entry(win, width=30)
        ent_serial.pack(pady=2)
        ent_serial.focus()
        entries['serial'] = ent_serial
        
        if needs_tag:
            ttk.Label(win, text="Asset Tag (Optional):").pack(pady=2)
            ent_asset = ttk.Entry(win, width=30)
            ent_asset.pack(pady=2)
            entries['asset_tag'] = ent_asset

        if extra_fields:
            for field_key, field_label in extra_fields.items():
                ttk.Label(win, text=field_label).pack(pady=2)
                ent = ttk.Entry(win, width=30)
                ent.pack(pady=2)
                entries[field_key] = ent
        
        def submit():
            data = {}
            for key, ent in entries.items():
                val = ent.get().strip()
                data[key] = val
                
                # Validation: Serial is always required
                if key == 'serial' and not val:
                    return
                # Extra fields are required
                if extra_fields and key in extra_fields and not val:
                    messagebox.showerror("Missing Field", f"{key} is required.")
                    return

            win.destroy()
            threading.Thread(target=callback, kwargs=data, daemon=True).start()

        ttk.Button(win, text="Process", command=submit).pack(pady=20)

    # ==========================
    # JOB FUNCTIONS
    # ==========================
    def open_inventory_window(self):
        self.create_input_window("Return to Inventory", self.process_inventory, needs_tag=True)

    def process_inventory(self, serial, asset_tag, **kwargs):
        self.log(f"Starting Inventory Job for {serial}")
        asset_id, record = self.find_and_get_asset(serial)
        if not asset_id: return

        if record.get('StatusID') == 1847:
            self.log("Asset is already in Inventory status.")
        else:
            self.log("Updating status to Inventory...")
            payload = record.copy()
            payload['StatusID'] = 1847
            payload['OwningCustomerID'] = "00000000-0000-0000-0000-000000000000"
            payload['OwningDepartmentID'] = 0
            payload['LocationID'] = 19060
            payload['LocationRoomID'] = 611719
            
            prefix = "s2"
            if 'Apple' in str(record.get('ManufacturerName', '')): prefix = "m2"
            final_tag = asset_tag if asset_tag else record.get('Tag')
            payload['Name'] = f"{prefix}-inv-{final_tag}"

            if self.send_update(asset_id, payload):
                self.remove_users(asset_id)
                self.add_feed_comment(asset_id, "Returned to inventory via Script")
                messagebox.showinfo("Success", f"{serial} returned to inventory.")

    def open_dispose_window(self):
        self.create_input_window("Dispose Asset", self.process_dispose, needs_tag=True)

    def process_dispose(self, serial, asset_tag, **kwargs):
        self.log(f"Starting Dispose Job for {serial}")
        asset_id, record = self.find_and_get_asset(serial)
        if not asset_id: return

        if record.get('StatusID') == 1850:
            self.log("Asset is already Disposed.")
        else:
            self.log("Disposing asset...")
            payload = record.copy()
            payload['StatusID'] = 1850
            payload['OwningCustomerID'] = "00000000-0000-0000-0000-000000000000"
            payload['OwningDepartmentID'] = 0
            payload['LocationID'] = ""

            final_tag = asset_tag if asset_tag else record.get('Tag')
            payload['Name'] = f"disposed-{final_tag}"

            disposal_date = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
            payload['Attributes'] = self.update_attributes(record, 117960, disposal_date)

            if self.send_update(asset_id, payload):
                self.remove_users(asset_id)
                self.add_feed_comment(asset_id, "System disposed via Script")
                messagebox.showinfo("Success", f"{serial} disposed.")

    def open_retire_window(self):
        extra = {'netid': 'Retiree NetID:', 'ticket': 'TDX Ticket Number:'}
        self.create_input_window("Retire Asset", self.process_retire, needs_tag=True, extra_fields=extra)

    def process_retire(self, serial, asset_tag, netid, ticket, **kwargs):
        self.log(f"Starting Retire Job for {serial}")
        asset_id, record = self.find_and_get_asset(serial)
        if not asset_id: return

        self.log("Retiring asset...")
        payload = record.copy()
        payload['StatusID'] = 1849
        payload['OwningCustomerID'] = "00000000-0000-0000-0000-000000000000"
        payload['OwningDepartmentID'] = 0
        payload['LocationID'] = ""

        final_tag = asset_tag if asset_tag else record.get('Tag')
        payload['Name'] = f"retired-{netid}-{final_tag}"

        retire_date = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        payload['Attributes'] = self.update_attributes(record, 121589, retire_date)

        if self.send_update(asset_id, payload):
            self.remove_users(asset_id)
            try:
                self.log(f"Linking Ticket {ticket}...")
                self.session.post(f"{self.tdx_base}api/1154/assets/{asset_id}/tickets/{ticket}")
            except Exception as e:
                self.log(f"Failed to link ticket: {e}")
            self.add_feed_comment(asset_id, f"System retired for {netid}")
            messagebox.showinfo("Success", f"{serial} retired and linked to ticket {ticket}.")

if __name__ == "__main__":
    root = tk.Tk()
    app = InventoryApp(root)
    root.mainloop()