# Mapsec

Modular mapping and security reconnaissance framework.

## Features

- **Plugin-based architecture** - Extend with custom plugins
- **Parallel execution** - Run multiple scans simultaneously
- **VirusTotal integration** - Threat intelligence lookups
- **DNS enumeration** - Record resolution and subdomain brute force
- **Port scanning** - Pure Python port scanner (no nmap required)
- **GUI interface** - Modern graphical interface with tabbed results

## Installation

```bash
# Clone the repository
git clone https://github.com/luizpetry/MapSec.git
cd mapsec

# Install in development mode
pip install -e .
```

## Requirements

- Python 3.11+
- VT_API_KEY environment variable (for VirusTotal plugin)

## Usage

### GUI

```bash
# Launch graphical interface
mapsec-gui
```

**GUI Features:**
- Tabbed results display — one tab per plugin
- Port scan results with service detection
- DNS records organized by type (A, AAAA, MX, NS, TXT)
- VirusTotal threat analysis with visual indicators
- Export results to JSON

### CLI

```bash
# Basic scan
mapsec scan example.com

# Scan with specific plugins
mapsec scan example.com --plugins nmap,dns

# Save report to file
mapsec scan example.com -o report.json

# List available plugins
mapsec plugins

# Show version
mapsec version
```

## Configuration

### VirusTotal API Key

The VT plugin requires an API key. You can configure it via:

1. **GUI**: Click "Settings" button → Enter your API key
2. **Environment variable**:
   ```bash
   export VT_API_KEY="your_api_key_here"
   ```

Get a free key at [virustotal.com](https://www.virustotal.com/gui/join-us)

## Plugin Development

Create a new plugin by extending `BasePlugin`:

```python
from mapsec.core.plugin import BasePlugin, register_plugin

@register_plugin
class MyPlugin(BasePlugin):
    name = "my-plugin"
    description = "My custom plugin"

    async def run(self, target: str) -> dict:
        # Your plugin logic here
        return {"result": "data"}
```

## Project Structure

```
mapsec/
├── mapsec/
│   ├── __init__.py
│   ├── cli.py              # CLI interface
│   ├── core/
│   │   ├── engine.py       # Pipeline orchestrator
│   │   ├── plugin.py       # Plugin base + registry
│   │   └── models.py       # Pydantic models
│   ├── plugins/
│   │   ├── nmap_scan.py    # Port scanner (pure Python)
│   │   ├── dns_enum.py     # DNS enumeration
│   │   └── vt_lookup.py    # VirusTotal lookup
│   ├── gui/
│   │   ├── __init__.py
│   │   ├── __main__.py
│   │   ├── app.py          # GUI application
│   │   └── results_panel.py # Tabbed results display
│   └── output/
│       └── json_writer.py  # JSON output
├── pyproject.toml
├── mapsec.ico
├── Mapsec.exe              # Standalone build
├── .env.example
├── .gitignore
└── README.md
```

## Building Standalone Executable

```bash
# Install PyInstaller
pip install pyinstaller

# Build .exe
pyinstaller --onefile --windowed --name "Mapsec" --icon mapsec.ico --add-data "mapsec.ico;." --collect-all customtkinter
```

## License

MIT
