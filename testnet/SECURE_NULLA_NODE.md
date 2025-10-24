# Securing a Server Running a Nulla Node (User + Port)

Assumptions:
- Linux host (e.g., Ubuntu/Debian)
- P2P port: 30333/TCP
- Goal: only open what’s needed and avoid running as root

## 1) Create a dedicated non-root user
```bash
# Create a user to run the node
sudo adduser <your-nulla-username>

# Optional: allow admin via sudo (use only if needed)
sudo usermod -aG sudo <your-nulla-username>
```

Recommended SSH hygiene (keep it simple):
- Use SSH keys for the user just created.
- Avoid password logins and root SSH access when possible.

Assumptions:

- ssh service on port 22
- direct access to the terminal in case of recovery
  
## 2) Open only the required ports (UFW)
```bash
# Install and set safe defaults
sudo apt -y install ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH (22). If you can, restrict to your IP:
# sudo ufw allow from <your-ip>/32 to any port 22 proto tcp
sudo ufw allow 22/tcp

# Allow NULLA P2P
sudo ufw allow 30333/tcp

# Enable and check
sudo ufw enable
sudo ufw status verbose
```

Notes:

- Keep RPC/WS/metrics closed to the internet (don’t open 9933/9944/9615).
- Run your node process as the  user created (not root).
