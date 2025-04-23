#!/usr/bin/env python3
# banner.py - ASCII art banner module for InsPect

ascii_banner = r"""

░        ░░   ░░░  ░░░      ░░░       ░░░        ░░░      ░░░        ░
▒▒▒▒  ▒▒▒▒▒    ▒▒  ▒▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒  ▒▒▒▒▒  ▒▒▒▒
▓▓▓▓  ▓▓▓▓▓  ▓  ▓  ▓▓▓      ▓▓▓       ▓▓▓      ▓▓▓▓  ▓▓▓▓▓▓▓▓▓▓▓  ▓▓▓▓
████  █████  ██    ████████  ██  ████████  ████████  ████  █████  ████
█        ██  ███   ███      ███  ████████        ███      ██████  ████

          IP & Domain Inspection and Intelligence Tool
"""

def print_banner(use_color=True):
    """
    Print the InsPect ASCII banner.
    
    Args:
        use_color (bool): Whether to use color formatting (requires rich library)
    """
    try:
        if use_color:
            from rich.console import Console
            from rich.text import Text
            
            console = Console()
            text = Text(ascii_banner)
            text.stylize("bold blue")
            console.print(text)
        else:
            raise ImportError("Using plain text mode")
    except ImportError:
        # Fallback to plain text if rich is not available
        print(ascii_banner)

# Execute only if run as a script
if __name__ == "__main__":
    print_banner()
    print("\nInsPect - IP Address and Domain Investigation Tool")
    print("https://github.com/fredycibersec/InsPect")




#
#░        ░░   ░░░  ░░░      ░░░       ░░░        ░░░      ░░░        ░
#▒▒▒▒  ▒▒▒▒▒    ▒▒  ▒▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒  ▒▒▒▒▒  ▒▒▒▒
#▓▓▓▓  ▓▓▓▓▓  ▓  ▓  ▓▓▓      ▓▓▓       ▓▓▓      ▓▓▓▓  ▓▓▓▓▓▓▓▓▓▓▓  ▓▓▓▓
#████  █████  ██    ████████  ██  ████████  ████████  ████  █████  ████
#█        ██  ███   ███      ███  ████████        ███      ██████  ████
