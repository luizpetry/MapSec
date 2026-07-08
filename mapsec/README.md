# Mapsec

Modular mapping and security reconnaissance framework.

## Features

- **Plugin-based architecture** - Extend with custom plugins
- **Parallel execution** - Run multiple scans simultaneously
- **VirusTotal integration** - Threat intelligence lookups
- **DNS enumeration** - Record resolution and subdomain brute force
- **Nmap integration** - Port scanning and service detection

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd mapsec

# Install in development mode
pip install -e .

# Or install with dev dependencies
pip install -e ".[dev]"
```

## Requirements

- Python 3.11+
- nmap (for port scanning plugin)
- VT_API_KEY environment variable (for VirusTotal plugin)

## Usage

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

### Environment Variables

```bash
# VirusTotal API key (required for vt plugin)
export VT_API_KEY="your_api_key_here"
```

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
│   │   ├── nmap_scan.py    # Nmap wrapper
│   │   ├── dns_enum.py     # DNS enumeration
│   │   └── vt_lookup.py    # VirusTotal lookup
│   └── output/
│       └── json_writer.py  # JSON output
├── pyproject.toml
└── README.md
```

## License

MIT
