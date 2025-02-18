# WireGuard Peer Manager Documentation

## Table of Contents
1. [Introduction](#introduction)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Folder Structure](#folder-structure)
5. [Configuration](#configuration)
6. [Deployment](#deployment)
7. [Usage](#usage)
8. [Troubleshooting](#troubleshooting)
9. [Complete Code](#complete-code)

---

## Introduction

This document provides step-by-step instructions to set up and deploy the **WireGuard Peer Manager** web application. This application, built using Python and Flask, interacts with a Mikrotik router’s API to manage WireGuard peers. It allows you to:

- Configure your Mikrotik router
- Generate new WireGuard peers
- Download client configuration files
- Display QR codes for client configurations
- Delete existing peers  
- Regenerate client configurations for peers created before using the app

---

## Prerequisites

- **Operating System:** Linux, Windows, or macOS.
- **Python:** Version 3.8 or higher.
- **Mikrotik Router:** Must run RouterOS v7 or later (WireGuard is supported only on v7+).
- **Basic Knowledge:** Familiarity with Python, the command line, and networking concepts.

---

## Installation

1. **Install Python**  
   Download and install Python from [python.org](https://www.python.org/downloads/) if it is not already installed.

2. **Create a Virtual Environment**  
   Open your terminal and run:
   ```bash
   python -m venv venv
   ```
   Activate the virtual environment:
   - On **Windows**:
     ```bash
     venv\Scripts\activate
     ```
   - On **macOS/Linux**:
     ```bash
     source venv/bin/activate
     ```

3. **Install Required Libraries**  
   Install the necessary packages using pip:
   ```bash
   pip install Flask PyNaCl librouteros waitress pillow qrcode[pil]
   ```
   - **Flask:** Web framework.
   - **PyNaCl:** For generating WireGuard keys.
   - **librouteros:** For interacting with the Mikrotik router API.
   - **waitress:** Production-ready WSGI server.
   - **pillow:** For image processing (required by qrcode).
   - **qrcode:** For generating QR codes.

---

## Folder Structure

Create a project directory with the following structure:

```
wireguard-peer-manager/
├── app.py
├── venv/                # Your virtual environment directory.
└── templates/
    └── index.html
```

- **app.py**: Contains the Flask application code.
- **templates/index.html**: Contains the HTML template for the web interface.
- **venv/**: Virtual environment directory.

---

## Configuration

- Open `app.py` and update the secret key:
  ```python
  app.secret_key = "replace_with_a_secure_random_secret"
  ```
  Replace `"replace_with_a_secure_random_secret"` with a strong, unique string.

- No additional configuration is required inside the code.

---

## Deployment

1. **Run the Application Locally**  
   Ensure your virtual environment is activated, then run:
   ```bash
   python app.py
   ```
   This will start the application on port 5000. Open your browser and navigate to `http://localhost:5000`.

2. **Using a Production Server**  
   You can deploy using Waitress or Gunicorn. For example, using Waitress:
   ```bash
   waitress-serve --listen=0.0.0.0:5000 app:app
   ```
   Make sure your firewall permits traffic on port 5000.

3. **Deploy on a Web Server**  
   You may deploy the app on any server that supports Python applications. For production, consider using HTTPS.

---

## Usage

1. **Configure the Router**  
   - Navigate to the **Config** tab.
   - Enter your Mikrotik router’s IP (or domain), username, and password.
   - The app will automatically detect (or create) the WireGuard interface and display its settings.

2. **Generate a Peer**  
   - Switch to the **Generate** tab.
   - Enter a unique peer name and click **Generate Config**.
   - A new peer is created on the router and its client configuration is generated and stored in the session.
   - The generated configuration is displayed in a table along with the peer's ID, name (comment), and allowed address.
   - For peers created before using this app (i.e. without a stored configuration), a **Regenerate Config** option is available.

3. **Peer Actions**  
   - **Download Config:** Download the client configuration file.
   - **Show QR Code:** Display a QR code for the client configuration.
   - **Regenerate Config:** Regenerate a client configuration for existing peers.
   - **Delete:** Remove the peer from the router.

---

## Troubleshooting

- **Download/QR Code for Existing Peers:**  
  For peers that existed before using the app, their client configuration is not stored in the session. Use the **Regenerate Config** option to generate and store a new configuration.

- **Dependencies:**  
  Ensure all required libraries are installed. If QR code generation fails, verify that Pillow is installed.

- **RouterOS Permissions:**  
  Confirm that your API user on the Mikrotik router has the necessary permissions to create, update, and delete WireGuard peers.

- **Session Storage:**  
  The app uses session storage (cookie-based) for storing generated configurations. In a production environment, consider using a persistent database.

---

## Complete Code

### app.py
```python
from flask import Flask, render_template, request, session, redirect, url_for, send_file, Response
import base64
import ipaddress
import logging
import time
import io

import nacl.utils
import nacl.bindings
from librouteros import connect

import qrcode

app = Flask(__name__)
app.config['DEBUG'] = False
app.secret_key = "replace_with_a_secure_random_secret"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
if not logger.handlers:
    logger.addHandler(console_handler)
else:
    logger.addHandler(console_handler)

def generate_keypair():
    private_key = nacl.utils.random(32)
    public_key = nacl.bindings.crypto_scalarmult_base(private_key)
    return (base64.b64encode(private_key).decode("ascii"),
            base64.b64encode(public_key).decode("ascii"))

def get_next_available_ip(api, wg_subnet):
    used_ips = set()
    try:
        peers = list(api(cmd="/interface/wireguard/peers/print"))
    except Exception as e:
        logger.error(f"API connection error: {e}")
        raise Exception(f"API connection error: {e}")
    for peer in peers:
        allowed = peer.get("allowed-address")
        if allowed:
            for addr in allowed.split(","):
                addr = addr.strip()
                if "/" in addr:
                    ip_str = addr.split("/")[0]
                    used_ips.add(ip_str)
    network = ipaddress.ip_network(wg_subnet, strict=False)
    server_ip = str(list(network.hosts())[0])
    for ip in network.hosts():
        ip_str = str(ip)
        if ip_str == server_ip:
            continue
        if ip_str not in used_ips:
            return ip_str
    raise Exception("No available IP addresses found in the subnet.")

def add_peer(api, interface, peer_comment, public_key, allowed_address):
    params = {
        "interface": interface,
        "comment": peer_comment,
        "public-key": public_key,
        "allowed-address": f"{allowed_address}/32"
    }
    try:
        response = list(api(cmd="/interface/wireguard/peers/add", **params))
        logger.info(f"Peer creation response: {response}")
        return response
    except Exception as e:
        logger.error(f"Failed to add peer: {e}")
        raise Exception(f"Failed to add peer to router: {e}")

def generate_client_config(client_private_key, client_address, server_public_key, server_endpoint, allowed_ips="0.0.0.0/0", dns="1.1.1.1"):
    config = f"""[Interface]
PrivateKey = {client_private_key}
Address = {client_address}/32
DNS = {dns}

[Peer]
PublicKey = {server_public_key}
Endpoint = {server_endpoint}
AllowedIPs = {allowed_ips}
PersistentKeepalive = 25
"""
    return config

def get_current_peers(api):
    try:
        peers = list(api(cmd="/interface/wireguard/peers/print"))
    except Exception as e:
        logger.error(f"Error fetching peers: {e}")
        peers = []
    return peers

@app.route("/", methods=["GET", "POST"])
def index():
    error = None
    current_peers = []
    active_tab = request.args.get("active_tab", "config")
    config_data = session.get('config_data', None)
    peer_configs = session.get("peer_configs", {})

    if request.method == "POST":
        form_type = request.form.get("form_type")
        if form_type == "config":
            router_ip = request.form.get("router_ip", "").strip()
            router_user = request.form.get("router_user", "").strip()
            router_pass = request.form.get("router_pass", "").strip()
            missing_fields = []
            if not router_ip:
                missing_fields.append("Router IP/Domain")
            if not router_user:
                missing_fields.append("Router Username")
            if not router_pass:
                missing_fields.append("Router Password")
            if missing_fields:
                error = "The following configuration fields are required: " + ", ".join(missing_fields)
            else:
                try:
                    logger.info(f"Connecting to router {router_ip} as {router_user}")
                    api = connect(username=router_user, password=router_pass, host=router_ip)
                    interfaces = list(api(cmd="/interface/wireguard/print"))
                    logger.info(f"Found {len(interfaces)} WireGuard interface(s)")
                    if not interfaces:
                        logger.info("No WireGuard interface found. Attempting to create one...")
                        router_private_key = nacl.utils.random(32)
                        router_private_key_b64 = base64.b64encode(router_private_key).decode("ascii")
                        create_params = {
                            "name": "wireguard1",
                            "listen-port": 51820,
                            "private-key": router_private_key_b64
                        }
                        try:
                            logger.info(f"Creating WireGuard interface with parameters: {create_params}")
                            result = list(api(cmd="/interface/wireguard/add", **create_params))
                            logger.info(f"Interface creation result: {result}")
                        except Exception as e:
                            logger.error(f"Error creating WireGuard interface: {e}")
                            raise Exception("Failed to create WireGuard interface. Ensure your router supports WireGuard (RouterOS v7+) and your user has sufficient permissions.")
                        time.sleep(1)
                        interfaces = list(api(cmd="/interface/wireguard/print"))
                        logger.info(f"After creation, found {len(interfaces)} WireGuard interface(s)")
                        if not interfaces:
                            raise Exception("Unable to create or retrieve a WireGuard interface from the router. Check if your router supports WireGuard (RouterOS v7+) and if your account has the required permissions.")
                    interface = next((i for i in interfaces if i.get("name") == "wireguard1"), interfaces[0])
                    server_public_key = interface.get("public-key")
                    if not server_public_key:
                        raise Exception("Failed to retrieve WireGuard public key from the router.")
                    all_addresses = list(api(cmd="/ip/address/print"))
                    addresses = [addr for addr in all_addresses if addr.get("interface") == interface.get("name")]
                    if addresses:
                        wg_subnet = addresses[0].get("address")
                    else:
                        default_address = "192.168.99.1/24"
                        api(cmd="/ip/address/add", address=default_address, interface=interface.get("name"))
                        wg_subnet = default_address
                    listen_port = interface.get("listen-port", 51820)
                    server_endpoint = f"{router_ip}:{listen_port}"
                    config_data = {
                        "router_ip": router_ip,
                        "router_user": router_user,
                        "router_pass": router_pass,
                        "wg_interface": interface.get("name"),
                        "server_public_key": server_public_key,
                        "server_endpoint": server_endpoint,
                        "wg_subnet": wg_subnet
                    }
                    session['config_data'] = config_data
                    session["peer_configs"] = {}
                    logger.info("Configuration successfully saved.")
                    return redirect(url_for("index", active_tab="config"))
                except Exception as ex:
                    error = str(ex)
                    return redirect(url_for("index", active_tab="config"))
        elif form_type == "generate":
            if not config_data:
                error = "Please configure the router settings first in the Config tab."
                return redirect(url_for("index", active_tab="config"))
            else:
                peer_name = request.form.get("peer_name", "").strip()
                if not peer_name:
                    error = "Peer name is required."
                    return redirect(url_for("index", active_tab="generate"))
                else:
                    try:
                        api = connect(username=config_data["router_user"],
                                      password=config_data["router_pass"],
                                      host=config_data["router_ip"])
                        current_peers = get_current_peers(api)
                        client_ip = get_next_available_ip(api, config_data["wg_subnet"])
                        client_private_key, client_public_key = generate_keypair()
                        response = add_peer(api, config_data["wg_interface"], peer_name, client_public_key, client_ip)
                        peer_id = None
                        if response and isinstance(response, list) and len(response) > 0:
                            peer_id = response[0].get("ret")
                        config_generated = generate_client_config(client_private_key, client_ip,
                                                                  config_data["server_public_key"],
                                                                  config_data["server_endpoint"])
                        peer_configs = session.get("peer_configs", {})
                        if peer_id:
                            peer_configs[peer_id] = config_generated
                        session["peer_configs"] = peer_configs
                        session["config_generated"] = config_generated
                        return redirect(url_for("index", active_tab="generate"))
                    except Exception as ex:
                        error = str(ex)
                        return redirect(url_for("index", active_tab="generate"))
    else:
        if config_data:
            try:
                api = connect(username=config_data["router_user"],
                              password=config_data["router_pass"],
                              host=config_data["router_ip"])
                current_peers = get_current_peers(api)
            except Exception as ex:
                error = str(ex)
    return render_template("index.html",
                           error=error,
                           peers=current_peers,
                           config_data=config_data,
                           active_tab=active_tab,
                           peer_configs=session.get("peer_configs", {}))

@app.route("/download/<peer_id>")
def download_config(peer_id):
    peer_configs = session.get("peer_configs", {})
    config = peer_configs.get(peer_id)
    if not config:
        return f"Configuration not found for peer ID {peer_id}. Please use the 'Regenerate Config' option.", 404
    return Response(config, mimetype="text/plain",
                    headers={"Content-Disposition": f"attachment;filename=wg_client_{peer_id}.conf"})

@app.route("/qrcode/<peer_id>")
def qrcode_config(peer_id):
    peer_configs = session.get("peer_configs", {})
    config = peer_configs.get(peer_id)
    if not config:
        return f"Configuration not found for peer ID {peer_id}. Please use the 'Regenerate Config' option.", 404
    try:
        img = qrcode.make(config)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        return send_file(buf, mimetype="image/png")
    except Exception as e:
        logger.error(f"Error generating QR code: {e}")
        return "Error generating QR code", 500

@app.route("/regenerate/<peer_id>")
def regenerate_config(peer_id):
    config_data = session.get('config_data', None)
    if not config_data:
        return redirect(url_for("index", active_tab="generate"))
    try:
        api = connect(username=config_data["router_user"],
                      password=config_data["router_pass"],
                      host=config_data["router_ip"])
        client_private_key, client_public_key = generate_keypair()
        api(cmd="/interface/wireguard/peers/set", **{".id": peer_id, "public-key": client_public_key})
        peers = list(api(cmd="/interface/wireguard/peers/print", **{".id": peer_id}))
        if not peers:
            raise Exception("Peer not found.")
        peer_info = peers[0]
        allowed_address = peer_info.get("allowed-address")
        if allowed_address and "/" in allowed_address:
            allowed_address = allowed_address.split("/")[0]
        config_generated = generate_client_config(client_private_key, allowed_address,
                                                  config_data["server_public_key"],
                                                  config_data["server_endpoint"])
        peer_configs = session.get("peer_configs", {})
        peer_configs[peer_id] = config_generated
        session["peer_configs"] = peer_configs
        return redirect(url_for("index", active_tab="generate"))
    except Exception as e:
        logger.error(f"Error regenerating config for peer {peer_id}: {e}")
        return str(e), 500

@app.route("/delete/<peer_id>")
def delete_peer(peer_id):
    config_data = session.get('config_data', None)
    if not config_data:
        return redirect(url_for("index", active_tab="generate"))
    try:
        api = connect(username=config_data["router_user"],
                      password=config_data["router_pass"],
                      host=config_data["router_ip"])
        response = list(api(cmd="/interface/wireguard/peers/remove", **{".id": peer_id}))
        logger.info(f"Delete response for peer {peer_id}: {response}")
        peer_configs = session.get("peer_configs", {})
        peer_configs.pop(peer_id, None)
        session["peer_configs"] = peer_configs
        return redirect(url_for("index", active_tab="generate"))
    except Exception as e:
        logger.error(f"Error deleting peer {peer_id}: {e}")
        return str(e), 500

if __name__ == "__main__":
    from waitress import serve
    logger.info("Starting production server using Waitress on port 5000...")
    serve(app, host="0.0.0.0", port=5000)
```

### templates/index.html
```html
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>WireGuard Peer Manager</title>
    <!-- Bootstrap CSS from CDN -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
  </head>
  <body>
    <div class="container mt-5">
      <h1>WireGuard Peer Manager</h1>
      {% if error %}
        <div class="alert alert-danger" role="alert">
          {{ error }}
        </div>
      {% endif %}
      <!-- Nav tabs -->
      <ul class="nav nav-tabs" id="myTab" role="tablist">
        <li class="nav-item">
          <a class="nav-link {% if active_tab == 'config' %}active{% endif %}" id="config-tab" data-toggle="tab" href="#config" role="tab">Config</a>
        </li>
        <li class="nav-item">
          <a class="nav-link {% if active_tab == 'generate' %}active{% endif %}" id="generate-tab" data-toggle="tab" href="#generate" role="tab">Generate</a>
        </li>
      </ul>
      <div class="tab-content mt-3">
        <!-- Config Tab -->
        <div class="tab-pane fade {% if active_tab == 'config' %}show active{% endif %}" id="config" role="tabpanel">
          <form method="post">
            <input type="hidden" name="form_type" value="config">
            <div class="form-group">
              <label for="router_ip">Router IP/Domain</label>
              <input type="text" class="form-control" id="router_ip" name="router_ip" placeholder="e.g., 192.168.10.1 or router.example.com" value="{{ config_data.router_ip if config_data }}">
            </div>
            <div class="form-group">
              <label for="router_user">Router Username</label>
              <input type="text" class="form-control" id="router_user" name="router_user" placeholder="admin" value="{{ config_data.router_user if config_data }}">
            </div>
            <div class="form-group">
              <label for="router_pass">Router Password</label>
              <input type="password" class="form-control" id="router_pass" name="router_pass" placeholder="password" value="{{ config_data.router_pass if config_data }}">
            </div>
            <button type="submit" class="btn btn-primary">Save Config</button>
          </form>
          {% if config_data %}
            <div class="mt-4">
              <h5>Detected Router WireGuard Settings:</h5>
              <ul>
                <li><strong>Interface:</strong> {{ config_data.wg_interface }}</li>
                <li><strong>Server Public Key:</strong> {{ config_data.server_public_key }}</li>
                <li><strong>WireGuard Subnet:</strong> {{ config_data.wg_subnet }}</li>
                <li><strong>Server Endpoint:</strong> {{ config_data.server_endpoint }}</li>
              </ul>
            </div>
          {% endif %}
        </div>
        <!-- Generate Tab -->
        <div class="tab-pane fade {% if active_tab == 'generate' %}show active{% endif %}" id="generate" role="tabpanel">
          <form method="post">
            <input type="hidden" name="form_type" value="generate">
            <div class="form-group">
              <label for="peer_name">Peer Name</label>
              <input type="text" class="form-control" id="peer_name" name="peer_name" placeholder="Enter Peer Name">
            </div>
            <button type="submit" class="btn btn-success">Generate Config</button>
          </form>
          <div class="mt-4">
            <h3>Current Peers on Router</h3>
            {% if peers %}
              <table class="table">
                <thead>
                  <tr>
                    <th>Peer ID</th>
                    <th>Name (Comment)</th>
                    <th>Allowed Address</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {% for peer in peers %}
                    <tr>
                      <td>{{ peer.get(".id") }}</td>
                      <td>{{ peer.get("comment", "Unnamed Peer") }}</td>
                      <td>{{ peer.get("allowed-address", "N/A") }}</td>
                      <td>
                        {% if peer_configs[peer.get(".id")] is defined %}
                          <a href="{{ url_for('download_config', peer_id=peer.get('.id')) }}" class="btn btn-sm btn-primary">Download Config</a>
                          <a href="{{ url_for('qrcode_config', peer_id=peer.get('.id')) }}" class="btn btn-sm btn-info">Show QR Code</a>
                        {% else %}
                          <a href="{{ url_for('regenerate_config', peer_id=peer.get('.id')) }}" class="btn btn-sm btn-warning">Regenerate Config</a>
                        {% endif %}
                        <a href="{{ url_for('delete_peer', peer_id=peer.get('.id')) }}" class="btn btn-sm btn-danger" onclick="return confirm('Are you sure you want to delete this peer?');">Delete</a>
                      </td>
                    </tr>
                  {% endfor %}
                </tbody>
              </table>
            {% else %}
              <p>No peers found.</p>
            {% endif %}
          </div>
          {% if session.config_generated %}
            <div class="mt-4">
              <h3>Newly Generated Client Config</h3>
              <pre>{{ session.config_generated }}</pre>
            </div>
          {% endif %}
        </div>
      </div>
    </div>
    <!-- Bootstrap JS and dependencies -->
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.2/dist/js/bootstrap.bundle.min.js"></script>
  </body>
</html>
```

---

## Deployment Instructions

1. **Clone/Copy the Project**  
   Place the files (`app.py` and the `templates/` directory with `index.html`) in a project directory, e.g., `wireguard-peer-manager/`.

2. **Create and Activate a Virtual Environment**  
   ```bash
   python -m venv venv
   source venv/bin/activate   # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**  
   ```bash
   pip install Flask PyNaCl librouteros waitress pillow qrcode[pil]
   ```

4. **Run the Application**  
   To run the app locally, execute:
   ```bash
   python app.py
   ```
   For production, use Waitress:
   ```bash
   waitress-serve --listen=0.0.0.0:5000 app:app
   ```

5. **Access the Application**  
   Open your browser and navigate to `http://localhost:5000` (or your server's IP/domain on port 5000).

---

## Final Notes

- The application uses session storage to manage generated client configurations. For persistent storage, consider using a database.
- Ensure your Mikrotik router supports WireGuard (RouterOS v7+) and that your API user has the necessary permissions.
- If you encounter issues with QR code generation, verify that Pillow is installed.
- Update the secret key in `app.py` to a strong, unique value for production use.
- The "Regenerate Config" feature allows you to generate a new configuration for peers that existed before using this app.

Happy Deploying!
