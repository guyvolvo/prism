# Prism Framework - Color Palette

from colorama import Fore, Back, Style, init

init(autoreset=True)


class PrismColors:

    # Titles and Headers
    HEADER = Fore.MAGENTA + Style.BRIGHT

    # Risk Levels (Based on Entropy 7.2 threshold)
    CRITICAL = Fore.RED + Style.BRIGHT  # High Entropy / Malicious YARA
    WARNING = Fore.YELLOW + Style.BRIGHT  # Heuristic Triggers (Macros/JS)
    SUCCESS = Fore.GREEN + Style.BRIGHT  # Low Entropy / Clean

    # Metadata and Info
    INFO = Fore.CYAN
    DIM = Style.DIM
    RESET = Style.RESET_ALL