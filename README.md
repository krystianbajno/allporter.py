# Port Scanner and Payload Sender

```
           _      _      _____   ____  _____ _______ ______ _____  
     /\   | |    | |    |  __ \ / __ \|  __ \__   __|  ____|  __ \ 
    /  \  | |    | |    | |__) | |  | | |__) | | |  | |__  | |__) |
   / /\ \ | |    | |    |  ___/| |  | |  _  /  | |  |  __| |  _  / 
  / ____ \| |____| |____| |    | |__| | | \ \  | |  | |____| | \ \ 
 /_/    \_\______|______|_|     \____/|_|  \_\ |_|  |______|_|  \_\
                                                                   
                                                Krystian Bajno 2025
```

This Python script is designed to scan for open ports on a target host, allow users to interact with the open ports, and send payloads to those ports. It uses multi-threading to scan ports quickly and enables manual connection and communication through each open port. The script maintains connections to open ports, meaning that once a port is found open, the connection stays open for further interaction until explicitly closed.

## Features

- Scans all ports from 1 to 65535 or specific ports provided by the user.
- Avoids scanning or interacting with blocklisted ports defined in a simple text file (`blocklist.txt`).
- Keeps the connection open to a port once it's found to be open, allowing further interactions without needing to reconnect.
- Allows users to manually interact with open ports by typing commands.
- Send payloads to open ports.
- Allows reconnection to a port if the connection drops.
- Multi-threaded scanning to increase performance.

## Requirements

- Python 3.x
- No external libraries required (uses standard Python libraries only).

## Usage

```bash
python allporter.py <target_host> [ports]
