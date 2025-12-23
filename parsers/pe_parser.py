# Portable executables parser
# extract_sections: Use the pefile library to iterate through .text, .data, and .rsrc.
# check_imports: Look for suspicious API calls like VirtualAlloc or WriteProcessMemory.
# find_overlay: Check for extra data appended to the end of the file, -
# - a common place for malware to hide its payload.

# Integration with scanner.py
# For a PE file, you shouldn't just run entropy on the whole file. You should run it per section:
# .text section (code): High entropy (e.g., > 7.0) here strongly suggests a Packed or Encrypted executable.
# .rsrc section: High entropy here often means an encrypted secondary payload is being stored as a resource.
