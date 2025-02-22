#!/usr/bin/env python3
from flask import Flask, render_template, request, session, redirect, url_for, send_file, Response, flash, get_flashed_messages,jsonify
import base64
import ipaddress
import logging
import time
import io
import json
import os
import nacl.utils
import nacl.bindings
from librouteros import connect
from librouteros.exceptions import LibRouterosError
from ipaddress import ip_network, AddressValueError
from functools import wraps
from os import environ
# For QR code generation
import qrcode
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
app.config['DEBUG'] = False
app.secret_key = "replace_with_a_secure_random_secret"

# Set up logging to console
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

PROFILES_FILE = os.path.join(os.path.dirname(__file__), "profiles.json")
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def load_profiles():
    """Loads profiles from profiles.json. Returns an empty dict if file not found or error."""
    try:
        with open(PROFILES_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        logger.error("Error decoding profiles.json. Returning empty profile.")
        return {}
    except Exception as e:
        logger.error(f"Error loading profiles: {e}")
        return {}

def save_profiles(profiles):
    """Saves profiles to profiles.json."""
    try:
        with open(PROFILES_FILE, 'w') as f:
            json.dump(profiles, f, indent=4)
        logger.info(f"Profiles saved to {PROFILES_FILE}")
    except Exception as e:
        logger.error(f"Error saving profiles to {PROFILES_FILE}: {e}")

def get_assigned_ips(router_serial):
    """Get set of assigned IPs for a specific router"""
    profiles = load_profiles()
    profile = profiles.get(router_serial, {})
    return set(profile.get('assigned_ips', []))

def add_assigned_ip(router_serial, ip_address):
    """Add an IP address to the assigned IPs list"""
    profiles = load_profiles()
    profile = profiles.get(router_serial, {})
    
    # Initialize assigned_ips if it doesn't exist
    if 'assigned_ips' not in profile:
        profile['assigned_ips'] = []
    
    # Add the IP if it's not already in the list
    if ip_address not in profile['assigned_ips']:
        profile['assigned_ips'].append(ip_address)
    
    profiles[router_serial] = profile
    save_profiles(profiles)
    logger.info(f"Added IP {ip_address} to assigned IPs for router {router_serial}")

def get_next_available_ip(api, wg_subnet, router_serial):
    """
    Determine the next free IP address in the WireGuard subnet.
    Now includes tracking of assigned IPs in profiles.json
    """
    try:
        network = ipaddress.ip_network(wg_subnet, strict=False)
        assigned_ips = get_assigned_ips(router_serial)
        server_ip = str(list(network.hosts())[0])
        
        for ip in network.hosts():
            ip_str = str(ip)
            if ip_str == server_ip:
                continue
            if ip_str not in assigned_ips:
                add_assigned_ip(router_serial, ip_str)
                return ip_str
                
        raise Exception("No available IP addresses found in the subnet.")
    except Exception as e:
        logger.error(f"Error getting next available IP: {e}")
        raise
def validate_ip_ranges(ip_ranges_str):
    """
    Validate IP ranges in CIDR notation.
    Returns (valid_ranges, error_message)
    """
    if not ip_ranges_str or ip_ranges_str.strip() == '':
        return ['0.0.0.0/0'], None
        
    ip_ranges = [r.strip() for r in ip_ranges_str.split(',')]
    valid_ranges = []
    
    for ip_range in ip_ranges:
        try:
            network = ip_network(ip_range, strict=False)
            valid_ranges.append(str(network))
        except (AddressValueError, ValueError) as e:
            return None, f"Invalid IP range format: {ip_range}. Please use CIDR notation (e.g., 192.168.1.0/24)"
    
    return valid_ranges, None

def generate_keypair():
    """
    Generate a WireGuard keypair.
    Returns a tuple (client_private_key, client_public_key) as base64-encoded strings.
    """
    private_key = nacl.utils.random(32)
    public_key = nacl.bindings.crypto_scalarmult_base(private_key)
    return (base64.b64encode(private_key).decode("ascii"),
            base64.b64encode(public_key).decode("ascii"))

def add_peer(api, interface, peer_comment, public_key, client_ip):
    """
    Add a WireGuard peer with the exact client IP as allowed address
    """
    try:
        # Format the allowed address with /32 subnet mask for exact IP match
        allowed_address = f"{client_ip}/32"
        
        params = {
            "interface": interface,
            "comment": peer_comment,
            "public-key": public_key,
            "allowed-address": allowed_address  # Single IP address for MikroTik peer
        }
        
        response = list(api(cmd="/interface/wireguard/peers/add", **params))
        logger.info(f"Peer creation response: {response}")
        return response
        
    except Exception as e:
        logger.error(f"Failed to add peer: {e}")
        raise Exception(f"Failed to add peer to router: {e}")

def generate_client_config(client_private_key, client_address, server_public_key, server_endpoint, dns="1.1.1.1"):
    """
    Generate the WireGuard client configuration with full tunnel routing
    """
    config = f"""[Interface]
PrivateKey = {client_private_key}
Address = {client_address}/32
DNS = {dns}

[Peer]
PublicKey = {server_public_key}
Endpoint = {server_endpoint}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""
    return config

def get_current_peers(api):
    """
    Retrieve the list of WireGuard peers from the router.
    """
    try:
        peers = list(api(cmd="/interface/wireguard/peers/print"))
    except Exception as e:
        logger.error(f"Error fetching peers: {e}")
        peers = []
    return peers
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == environ.get('ADMIN_USER') and \
           password == environ.get('ADMIN_PASS'):
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials')
    
    return render_template('login.html')
@app.route('/logout')
def logout():
    # Clear the session
    session.clear()
    # Redirect to login page
    return redirect(url_for('login'))

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    error = None
    current_peers = []
    active_tab = request.args.get("active_tab", "config")
    config_data = None
    peer_configs = {}

    profiles = load_profiles()

    if request.method == "POST":
        form_type = request.form.get("form_type")
        
        if form_type == "config":
            router_ip = request.form.get("router_ip", "").strip()
            router_user = request.form.get("router_user", "").strip()
            router_pass = request.form.get("router_pass", "").strip()
            
            # Validate required fields
            missing_fields = []
            if not router_ip:
                missing_fields.append("Router IP/Domain")
            if not router_user:
                missing_fields.append("Router Username")
            if not router_pass:
                missing_fields.append("Router Password")
                
            if missing_fields:
                error = "The following configuration fields are required: " + ", ".join(missing_fields)
                flash(error, 'error')
            else:
                try:
                    logger.info(f"Connecting to router {router_ip} as {router_user}")
                    api = connect(username=router_user, password=router_pass, host=router_ip)

                    # Get router serial number
                    routerboard = api.path('system', 'routerboard')
                    routerboard_info = list(routerboard('print'))
                    logger.info(f"Routerboard info response: {routerboard_info}")

                    if not isinstance(routerboard_info, list) or not routerboard_info:
                        raise ValueError("Could not retrieve routerboard information")

                    serial_number = routerboard_info[0].get('serial-number')
                    if not serial_number:
                        raise ValueError("Could not retrieve serial number")
                    
                    logger.info(f"Router Serial Number: {serial_number}")

                    # Check/Create WireGuard interface
                    interfaces = list(api(cmd="/interface/wireguard/print"))
                    logger.info(f"Found {len(interfaces)} WireGuard interface(s)")
                    
                    if not interfaces:
                        logger.info("No WireGuard interface found. Creating one...")
                        router_private_key = nacl.utils.random(32)
                        router_private_key_b64 = base64.b64encode(router_private_key).decode("ascii")
                        
                        create_params = {
                            "name": "wireguard1",
                            "listen-port": 51820,
                            "private-key": router_private_key_b64
                        }
                        
                        try:
                            result = list(api(cmd="/interface/wireguard/add", **create_params))
                            logger.info(f"Interface creation result: {result}")
                            time.sleep(1)  # Wait for interface creation
                            interfaces = list(api(cmd="/interface/wireguard/print"))
                        except LibRouterosError as ros_err:
                            if "permission" in str(ros_err).lower():
                                raise PermissionError("API Permission Denied")
                            raise

                    # Get or create interface configuration
                    interface = next((i for i in interfaces if i.get("name") == "wireguard1"), interfaces[0])
                    server_public_key = interface.get("public-key")
                    if not server_public_key:
                        raise ValueError("Failed to retrieve WireGuard public key")

                    # Get or create IP address configuration
                    all_addresses = list(api(cmd="/ip/address/print"))
                    addresses = [addr for addr in all_addresses if addr.get("interface") == interface.get("name")]
                    
                    if addresses:
                        wg_subnet = addresses[0].get("address")
                    else:
                        default_address = "192.168.99.1/24"
                        api(cmd="/ip/address/add", address=default_address, interface=interface.get("name"))
                        wg_subnet = default_address

                    # Save configuration
                    config_data = {
                        "router_ip": router_ip,
                        "router_user": router_user,
                        "router_pass": router_pass,
                        "wg_interface": interface.get("name"),
                        "server_public_key": server_public_key,
                        "server_endpoint": f"{router_ip}:{interface.get('listen-port', 51820)}",
                        "wg_subnet": wg_subnet
                    }

                    # Update profiles
                    profile = profiles.get(serial_number, {})
                    peer_configs_profile = profile.get("peer_configs", {})
                    profile['config_data'] = config_data
                    profile['peer_configs'] = peer_configs_profile
                    profiles[serial_number] = profile
                    save_profiles(profiles)

                    session['config_data'] = config_data
                    session['router_serial'] = serial_number

                    logger.info("Configuration saved successfully")
                    flash('Configuration saved successfully!', 'success')
                    return redirect(url_for("index", active_tab="config"))

                except Exception as ex:
                    logger.error(f"Error in configuration: {ex}")
                    flash(str(ex), 'error')
                    return redirect(url_for("index", active_tab="config"))

        elif form_type == "generate":
            config_data = session.get('config_data')
            router_serial = session.get('router_serial')
            
            if not config_data or not router_serial:
                flash("Please configure the router settings first", 'error')
                return redirect(url_for("index", active_tab="config"))

            peer_name = request.form.get("peer_name", "").strip()
            if not peer_name:
                flash("Peer name is required", 'error')
                return redirect(url_for("index", active_tab="generate"))

            try:
                api = connect(
                    username=config_data["router_user"],
                    password=config_data["router_pass"],
                    host=config_data["router_ip"]
                )

                # Get next available IP and generate keys
                client_ip = get_next_available_ip(api, config_data["wg_subnet"], router_serial)
                client_private_key, client_public_key = generate_keypair()

                # Create peer with exact IP match
                response = add_peer(
                    api,
                    config_data["wg_interface"],
                    peer_name,
                    client_public_key,
                    client_ip
                )

                if response and isinstance(response, list) and len(response) > 0:
                    peer_id = response[0].get("ret")
                    if peer_id:
                        # Generate client configuration
                        config_generated = generate_client_config(
                            client_private_key,
                            client_ip,
                            config_data["server_public_key"],
                            config_data["server_endpoint"]
                        )

                        # Save peer configuration
                        profile = profiles.get(router_serial, {})
                        peer_configs_profile = profile.get("peer_configs", {})
                        peer_configs_profile[peer_id] = config_generated
                        profile["peer_configs"] = peer_configs_profile
                        profiles[router_serial] = profile
                        save_profiles(profiles)

                        session["config_generated"] = config_generated
                        flash(f'Peer "{peer_name}" generated successfully!', 'success')
                        return redirect(url_for("index", active_tab="generate"))

            except Exception as ex:
                logger.error(f"Error generating peer: {ex}")
                flash(f'Error generating peer: {ex}', 'error')
                return redirect(url_for("index", active_tab="generate"))

    # Get current configuration and peers for display
    if session.get('config_data'):
        config_data = session.get('config_data')
        router_serial = session.get('router_serial')
        
        if router_serial and router_serial in profiles:
            profile = profiles[router_serial]
            peer_configs = profile.get("peer_configs", {})
            
            try:
                api = connect(
                    username=config_data["router_user"],
                    password=config_data["router_pass"],
                    host=config_data["router_ip"]
                )
                current_peers = get_current_peers(api)
            except Exception as ex:
                logger.error(f"Error fetching peers: {ex}")
                flash(f'Error connecting to router: {ex}', 'error')

    return render_template(
        "index.html",
        error=error,
        peers=current_peers,
        config_data=config_data,
        active_tab=active_tab,
        peer_configs=peer_configs,
        flashed_messages=get_flashed_messages(with_categories=True)
    )

@app.route("/qrcode/<peer_id>")
def qrcode_config(peer_id):
    profiles = load_profiles()
    router_serial = session.get('router_serial')
    if not router_serial:
        return jsonify({
            'success': False,
            'error': 'Router serial number not found in session'
        }), 400
        
    profile = profiles.get(router_serial, {})
    peer_configs_profile = profile.get("peer_configs", {})
    config = peer_configs_profile.get(peer_id)
    
    if not config:
        return jsonify({
            'success': False,
            'error': f'Configuration not found for peer ID {peer_id}'
        }), 404
        
    try:
        img = qrcode.make(config)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        img_str = base64.b64encode(buf.getvalue()).decode()
        
        return jsonify({
            'success': True,
            'image_data': img_str
        })
        
    except Exception as e:
        logger.error(f"Error generating QR code: {e}")
        return jsonify({
            'success': False,
            'error': 'Error generating QR code'
        }), 500

@app.route("/download/<peer_id>")
def download_config(peer_id):
    profiles = load_profiles()
    router_serial = session.get('router_serial')
    if not router_serial:
        return "Router serial number not found in session.", 400
    profile = profiles.get(router_serial, {})
    peer_configs_profile = profile.get("peer_configs", {})
    config = peer_configs_profile.get(peer_id)

    if not config:
        return f"Configuration not found for peer ID {peer_id}.", 404

    peer_name_for_filename = "wireguard_config"
    config_data_session = session.get('config_data')
    if config_data_session:
        try:
            api = connect(username=config_data_session["router_user"], 
                        password=config_data_session["router_pass"], 
                        host=config_data_session["router_ip"])
            peers = get_current_peers(api)
            peer_info = next((p for p in peers if p['.id'] == peer_id), None)
            if peer_info and peer_info.get('comment'):
                peer_name_for_filename = peer_info['comment'].replace(" ", "_")
        except:
            logger.warning("Could not fetch peer comment for filename.")

    filename = f"{peer_name_for_filename}.conf"
    return Response(
        config,
        mimetype="text/plain",
        headers={"Content-disposition": f"attachment; filename={filename}"}
    )

@app.route("/delete/<peer_id>")
def delete_peer(peer_id):
    config_data = session.get('config_data', None)
    router_serial = session.get('router_serial')
    if not config_data or not router_serial:
        return redirect(url_for("index", active_tab="generate"))
    try:
        api = connect(username=config_data["router_user"],
                     password=config_data["router_pass"],
                     host=config_data["router_ip"])
        response = list(api(cmd="/interface/wireguard/peers/remove", **{".id": peer_id}))
        logger.info(f"Delete response for peer {peer_id}: {response}")
        
        # Remove peer configuration and update profiles
        profiles = load_profiles()
        profile = profiles.get(router_serial, {})
        peer_configs_profile = profile.get("peer_configs", {})
        
        if peer_id in peer_configs_profile:
            del peer_configs_profile[peer_id]
            profile["peer_configs"] = peer_configs_profile
            profiles[router_serial] = profile
            save_profiles(profiles)
        
        flash(f'Peer deleted successfully!', 'success')
        return redirect(url_for("index", active_tab="generate"))
    except Exception as e:
        logger.error(f"Error deleting peer {peer_id}: {e}")
        flash(f'Error deleting peer: {e}', 'error')
        return str(e), 500

if __name__ == "__main__":
    from waitress import serve
    logger.info("Starting production server using Waitress on port 5000...")
    serve(app, host="0.0.0.0", port=5000)
