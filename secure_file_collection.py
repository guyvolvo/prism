
import os
import pathlib
from typing import List, Tuple, Optional
from dataclasses import dataclass

try:
    from colors import PrismColors as PC
except ImportError:
    class PC:
        HEADER = '\033[95m'
        INFO = '\033[94m'
        SUCCESS = '\033[92m'
        WARNING = '\033[93m'
        CRITICAL = '\033[91m'
        RESET = '\033[0m'


@dataclass
class ValidationResult:
    is_valid: bool
    reason: str
    file_path: Optional[str] = None


class SecureFileCollector:

    MAX_PATH_LENGTH = 4096
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB

    BLOCKED_EXTENSIONS = {
        '.lnk',
        '.url',
        '.desktop'
    }

    # Special files/directories to skip
    SKIP_PATTERNS = {
        '__pycache__',
        '.git',
        '.svn',
        '.hg',
        'node_modules',
        '.venv',
        'venv',
        '.pytest_cache',
        '.tox',
        '.idea',
        '.vscode'
    }

    def __init__(self, max_file_size: int = MAX_FILE_SIZE, allow_large: bool = False):
        """
        Initialize the secure file collector.
        Args:
            max_file_size: Maximum allowed file size in bytes
            allow_large: Whether to allow files larger than max_file_size
        """
        self.max_file_size = max_file_size
        self.allow_large = allow_large
        self.stats = {
            'total_found': 0,
            'validated': 0,
            'skipped_symlinks': 0,
            'skipped_size': 0,
            'skipped_permissions': 0,
            'skipped_blocked_ext': 0,
            'skipped_invalid_path': 0
        }

    def validate_path_security(self, target_path: str, base_dir: Optional[str] = None) -> ValidationResult:

        try:
            # Convert to Path object
            path = pathlib.Path(target_path)

            # Check path length
            path_str = str(path)
            if len(path_str) > self.MAX_PATH_LENGTH:
                return ValidationResult(
                    is_valid=False,
                    reason=f"Path too long ({len(path_str)} > {self.MAX_PATH_LENGTH} chars)"
                )

            # Resolve to absolute path
            try:
                resolved_path = path.resolve()
            except (OSError, RuntimeError) as e:
                return ValidationResult(
                    is_valid=False,
                    reason=f"Path resolution failed: {e}"
                )

            # Check if path exists
            if not resolved_path.exists():
                return ValidationResult(
                    is_valid=False,
                    reason="Path does not exist"
                )

            # Check for path traversal if base_dir provided
            if base_dir:
                try:
                    base = pathlib.Path(base_dir).resolve()
                    # Check if resolved path is relative to base
                    if not self._is_path_within_base(resolved_path, base):
                        return ValidationResult(
                            is_valid=False,
                            reason="Path traversal detected (outside base directory)"
                        )
                except (ValueError, OSError) as e:
                    return ValidationResult(
                        is_valid=False,
                        reason=f"Base directory validation failed: {e}"
                    )

            return ValidationResult(
                is_valid=True,
                reason="Path validation passed",
                file_path=str(resolved_path)
            )

        except Exception as e:
            return ValidationResult(
                is_valid=False,
                reason=f"Validation error: {e}"
            )

    def validate_file_security(self, file_path: pathlib.Path) -> ValidationResult:

        if not file_path.is_file():
            return ValidationResult(
                is_valid=False,
                reason="Not a regular file"
            )

        if file_path.is_symlink():
            self.stats['skipped_symlinks'] += 1
            return ValidationResult(
                is_valid=False,
                reason="Symbolic link (security risk)"
            )

        # Check blocked extensions
        if file_path.suffix.lower() in self.BLOCKED_EXTENSIONS:
            self.stats['skipped_blocked_ext'] += 1
            return ValidationResult(
                is_valid=False,
                reason=f"Blocked extension: {file_path.suffix}"
            )

        # Check file permissions
        if not os.access(file_path, os.R_OK):
            self.stats['skipped_permissions'] += 1
            return ValidationResult(
                is_valid=False,
                reason="Permission denied (cannot read file)"
            )

        # Check file size
        try:
            file_size = file_path.stat().st_size

            # Skip empty files
            if file_size == 0:
                return ValidationResult(
                    is_valid=False,
                    reason="Empty file (0 bytes)"
                )

            # Check size limit
            if not self.allow_large and file_size > self.max_file_size:
                self.stats['skipped_size'] += 1
                size_mb = file_size / (1024 * 1024)
                limit_mb = self.max_file_size / (1024 * 1024)
                return ValidationResult(
                    is_valid=False,
                    reason=f"File too large ({size_mb:.1f}MB > {limit_mb:.1f}MB limit)"
                )

        except OSError as e:
            return ValidationResult(
                is_valid=False,
                reason=f"Could not stat file: {e}"
            )

        # All checks passed
        self.stats['validated'] += 1
        return ValidationResult(
            is_valid=True,
            reason="File validation passed",
            file_path=str(file_path)
        )

    def _is_path_within_base(self, path: pathlib.Path, base: pathlib.Path) -> bool:

        try:
            return path.is_relative_to(base)
        except AttributeError:

            try:
                path.relative_to(base)
                return True
            except ValueError:
                return False

    def _should_skip_directory(self, dir_path: pathlib.Path) -> bool:

        dir_name = dir_path.name.lower()
        return dir_name in self.SKIP_PATTERNS

    def collect_files(self, target: str, recursive: bool = False,
                      base_dir: Optional[str] = None, verbose: bool = False) -> Tuple[List[str], dict]:

        files_to_process = []

        validation = self.validate_path_security(target, base_dir)
        if not validation.is_valid:
            if verbose:
                print(f"{PC.CRITICAL}[!] Invalid target: {validation.reason}{PC.RESET}")
            return [], self.stats

        target_path = pathlib.Path(validation.file_path)

        if verbose:
            print(f"{PC.INFO}[*] Scanning target: {target_path}{PC.RESET}")

        if target_path.is_file():
            file_validation = self.validate_file_security(target_path)
            if file_validation.is_valid:
                files_to_process.append(file_validation.file_path)
                if verbose:
                    print(f"{PC.SUCCESS}[+] File validated: {target_path.name}{PC.RESET}")
            else:
                if verbose:
                    print(f"{PC.WARNING}[!] Skipped: {target_path.name} - {file_validation.reason}{PC.RESET}")

            self.stats['total_found'] = 1
            return files_to_process, self.stats

        # Handle directory
        if target_path.is_dir():
            if verbose:
                print(f"{PC.INFO}[*] Collecting files from directory...{PC.RESET}")

            try:
                if recursive:
                    # Recursive walk
                    for item in target_path.rglob("*"):
                        if item.is_dir():
                            # Skip special directories
                            if self._should_skip_directory(item):
                                if verbose:
                                    print(f"{PC.WARNING}[!] Skipping directory: {item.name}{PC.RESET}")
                                continue
                        elif item.is_file():
                            self.stats['total_found'] += 1

                            # Validate file
                            file_validation = self.validate_file_security(item)
                            if file_validation.is_valid:
                                files_to_process.append(file_validation.file_path)
                            elif verbose:
                                print(f"{PC.WARNING}[!] Skipped: {item.name} - {file_validation.reason}{PC.RESET}")
                else:
                    # Non-recursive (immediate children only)
                    for item in target_path.iterdir():
                        if item.is_file():
                            self.stats['total_found'] += 1

                            # Validate file
                            file_validation = self.validate_file_security(item)
                            if file_validation.is_valid:
                                files_to_process.append(file_validation.file_path)
                            elif verbose:
                                print(f"{PC.WARNING}[!] Skipped: {item.name} - {file_validation.reason}{PC.RESET}")

            except PermissionError as e:
                if verbose:
                    print(f"{PC.CRITICAL}[!] Permission denied accessing directory: {e}{PC.RESET}")
            except Exception as e:
                if verbose:
                    print(f"{PC.CRITICAL}[!] Error scanning directory: {e}{PC.RESET}")

        if verbose:
            print(f"{PC.SUCCESS}[+] Collection complete: {len(files_to_process)} files validated{PC.RESET}")
            if self.stats['total_found'] > len(files_to_process):
                skipped = self.stats['total_found'] - len(files_to_process)
                print(f"{PC.WARNING}[!] Skipped {skipped} files{PC.RESET}")

        return files_to_process, self.stats

    def print_collection_stats(self):
        """Print detailed collection statistics."""
        print(f"\n{PC.HEADER}{'=' * 60}{PC.RESET}")
        print(f"{PC.HEADER}FILE COLLECTION STATISTICS{PC.RESET}")
        print(f"{PC.HEADER}{'=' * 60}{PC.RESET}")
        print(f"Total files found:           {self.stats['total_found']}")
        print(f"{PC.SUCCESS}Files validated:             {self.stats['validated']}{PC.RESET}")

        if self.stats['skipped_symlinks'] > 0:
            print(f"{PC.WARNING}Skipped (symlinks):          {self.stats['skipped_symlinks']}{PC.RESET}")
        if self.stats['skipped_size'] > 0:
            print(f"{PC.WARNING}Skipped (too large):         {self.stats['skipped_size']}{PC.RESET}")
        if self.stats['skipped_permissions'] > 0:
            print(f"{PC.WARNING}Skipped (no permissions):    {self.stats['skipped_permissions']}{PC.RESET}")
        if self.stats['skipped_blocked_ext'] > 0:
            print(f"{PC.WARNING}Skipped (blocked extension): {self.stats['skipped_blocked_ext']}{PC.RESET}")
        if self.stats['skipped_invalid_path'] > 0:
            print(f"{PC.WARNING}Skipped (invalid path):      {self.stats['skipped_invalid_path']}{PC.RESET}")

        print(f"{PC.HEADER}{'=' * 60}{PC.RESET}\n")


def validate_before_processing(file_path: str, allow_large: bool = False) -> Tuple[bool, str]:

    collector = SecureFileCollector(allow_large=allow_large)

    path_validation = collector.validate_path_security(file_path)
    if not path_validation.is_valid:
        return False, path_validation.reason

    file_path_obj = pathlib.Path(path_validation.file_path)
    file_validation = collector.validate_file_security(file_path_obj)

    return file_validation.is_valid, file_validation.reason


