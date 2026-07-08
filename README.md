# rdp_validator-api# 🥝 RDP Validator API

Full NTLMv2 RDP credential validator. Deploy on Railway, call from extension.

## Endpoints

### `POST /check`
Validate single credential.

**Input:**
```json
{
  "target": "3.0.0.168",
  "port": 3389,
  "username": "Administrator",
  "password": "Summer2026!"
}