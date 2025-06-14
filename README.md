# moondeck-cli

A command-line interface for [MoonDeck](https://github.com/FrogTheFrog/moondeck) that allows you to manage and control game streaming hosts from the terminal. This CLI provides functionality to scan for hosts, pair with them, launch games, and manage streaming sessions without needing the Steam Deck UI.

> [!Warning]
> Archived as [MoonDeck implements CLI](https://github.com/FrogTheFrog/moondeck/pull/110)

## Features

- 🔍 **Host Discovery**: Automatically scan for available Apollo/Sunshine hosts on your network
- 🔗 **Host Pairing**: Pair with hosts using PIN-based authentication
- 🎮 **Game Launching**: Launch Steam games and non-Steam applications remotely
- 📱 **Stream Management**: Monitor and control active streaming sessions
- 💾 **Host Management**: Save, list, and manage multiple host configurations
- 🌐 **Wake-on-LAN**: Wake up sleeping hosts remotely
- ⚙️ **Configuration**: Flexible configuration with support for custom config files

## Prerequisites

1. **MoonDeck Buddy**: Install [MoonDeck Buddy](https://github.com/FrogTheFrog/moondeck-buddy) on your host PC
2. **Python 3.7+**: Required to run the CLI
3. **Network Access**: Ensure your client and host are on the same network or have proper network connectivity

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/ClassicOldSong/moondeck-cli.git
   cd moondeck-cli
   ```

2. Initialize the MoonDeck submodule:
   ```bash
   git submodule update --init --recursive
   ```

3. Download the cretificate file from https://github.com/FrogTheFrog/moondeck-keys/blob/main/moondeck_cert.pem and save to `./moondeck/defaults/python/ssl/moondeck_cert.pem`.

3. Run the CLI:
   ```bash
   python moondeck-cli.py --help
   ```

## Quick Start

1. **Scan for hosts**:
   ```bash
   python moondeck-cli.py scan
   ```

2. **Pair with a host**:
   ```bash
   python moondeck-cli.py pair --host <HOST_IP_OR_ID_OR_HOST_NAME> --pin 1234
   ```

3. **Set a default host** (optional):
   ```bash
   python moondeck-cli.py set-default <HOST_ID>
   ```

4. **Launch a game**:
   ```bash
   python moondeck-cli.py launch --app-id <STEAM_APP_ID>
   ```

## Commands

### Host Management

#### `scan`
Scan for available MoonDeck Buddy hosts on the network and update the local hosts database.

```bash
python moondeck-cli.py scan [--timeout SECONDS]
```

**Options:**
- `--timeout`: Scan timeout in seconds (default: 5.0)

#### `pair`
Pair with a MoonDeck Buddy host using PIN authentication.

```bash
python moondeck-cli.py pair --host <HOST> --pin <PIN> [OPTIONS]
```

**Options:**
- `--host`: Host ID, IP address, or hostname
- `--pin`: 4-digit pairing PIN (default: random)
- `--port`: Buddy port (default: 59999)
- `--client-id`: Custom client ID
- `--no-default`: Don't set this host as default after pairing

#### `list-hosts`
Display all saved hosts with their configuration details.

```bash
python moondeck-cli.py list-hosts
```

#### `set-default`
Set a host as the default for commands that don't specify a host.

```bash
python moondeck-cli.py set-default <HOST_ID>
```

#### `clear-default`
Clear the current default host setting.

```bash
python moondeck-cli.py clear-default
```

#### `wake`
Wake a host using Wake-on-LAN (requires MAC address).

```bash
python moondeck-cli.py wake [--host <HOST>]
```

### Game Management

#### `launch`
Launch a Steam game on the specified host.

```bash
python moondeck-cli.py launch --app-id <APP_ID> [OPTIONS]
```

**Options:**
- `--app-id`: Steam application ID (required)
- `--host`: Target host (uses default if not specified)
- `--port`: Buddy port (default: 59999)
- `--client-id`: Custom client ID
- `--no-big-picture`: Launch without Big Picture mode
- `--wait`: Wait for the game to quit and automatically end the stream

#### `list-apps`
List available GameStream applications on a host.

```bash
python moondeck-cli.py list-apps [--host <HOST>]
```

#### `list-non-steam`
List non-Steam games available on a host.

```bash
python moondeck-cli.py list-non-steam --user-id <USER_ID> [--host <HOST>]
```

**Options:**
- `--user-id`: Steam user ID (required)

### Stream Management

#### `app-status`
Get information about the currently running application on a host.

```bash
python moondeck-cli.py app-status [--host <HOST>]
```

#### `end-stream`
End the current game stream on a host.

```bash
python moondeck-cli.py end-stream [--host <HOST>]
```

## Configuration

### Config Files

The CLI uses JSON configuration files to store settings and host information:

- **config.json**: Main configuration file containing client ID, default host, and hosts file path
- **hosts.json**: Database of discovered and paired hosts

### Default Locations

- **Script mode**: Same directory as `moondeck-cli.py`
<!-- - **Executable mode**: Same directory as the executable -->

### Custom Config File

You can specify a custom configuration file location:

```bash
python moondeck-cli.py --config-file /path/to/custom/config.json <command>
```

### Configuration Structure

**config.json**:
```json
{
  "client_id": "unique-client-identifier",
  "hosts_file": "hosts.json",
  "default_host": "host-id-or-null"
}
```

**hosts.json**:
```json
{
  "HOST_ID": {
    "id": "HOST_ID",
    "uniqueId": "unique-host-identifier",
    "hostName": "Host Display Name",
    "address": "192.168.1.100",
    "buddy_port": 59999,
    "client_id": "paired-client-id",
    "mac": "AA:BB:CC:DD:EE:FF"
  }
}
```

## Examples

### Basic Workflow

1. **Discover hosts on your network**:
   ```bash
   python moondeck-cli.py scan
   ```

2. **Pair with your gaming PC**:
   ```bash
   python moondeck-cli.py pair --host 192.168.1.100 --pin 1234
   ```

3. **Set it as default**:
   ```bash
   python moondeck-cli.py set-default HOST_ID
   ```

4. **Launch a game** (e.g., Steam app ID 570 for Dota 2):
   ```bash
   python moondeck-cli.py launch --app-id 570
   ```

### Advanced Usage

**Launch a game and wait for it to finish**:
```bash
python moondeck-cli.py launch --app-id 570 --wait
```

**Wake a sleeping host and launch a game**:
```bash
python moondeck-cli.py wake --host gaming-pc
sleep 30  # Wait for host to boot
python moondeck-cli.py launch --app-id 570 --host gaming-pc
```

**Check what's currently running**:
```bash
python moondeck-cli.py app-status
```

**End a stream session**:
```bash
python moondeck-cli.py end-stream
```

## Troubleshooting

### Common Issues

1. **"No hosts found"**: Ensure Apollo/Sunshine is running on the host and both devices are on the same network
2. **"Pairing failed"**: Check that the PIN is correct and the host is ready for pairing
3. **"Host not found"**: Verify the host ID/IP is correct using `list-hosts`
4. **"Missing MAC address"**: The host needs to be properly paired to store MAC address for Wake-on-LAN

### Logging

The CLI generates logs in `cli.log` in the same directory as the script. Check this file for detailed error information.

### Network Requirements

- **Port 59999**: Default MoonDeck Buddy port (configurable)
- **UDP Broadcast**: Required for host discovery
- **Wake-on-LAN**: UDP port 9 for wake packets

## Related Projects

- [MoonDeck](https://github.com/FrogTheFrog/moondeck) - Steam Deck plugin for game streaming
- [MoonDeck Buddy](https://github.com/FrogTheFrog/moondeck-buddy) - Host-side companion application

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
