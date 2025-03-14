from Registry import Registry
import struct
import datetime

def decode_username(v_blob):
    """
    Decode the username from the SAM V value.
    
    The V value structure is assumed to be as follows:
      - At offset 0x0C (2 bytes): the length of the username in Unicode characters.
      - At offset 0x10 (4 bytes): the offset (in bytes) within the V blob where the username starts.
    
    Since the username is stored in UTF-16LE, the number of bytes to extract is (length * 2).
    """
    try:
        # Get the length in Unicode characters (2 bytes at offset 0x0C)
        username_length_chars = struct.unpack("<H", v_blob[0x0C:0x0E])[0]
        # Calculate the byte length (UTF-16LE: 2 bytes per character)
        username_length_bytes = username_length_chars * 2
        # Get the offset (4 bytes at offset 0x10) where the username starts
        username_offset = struct.unpack("<I", v_blob[0x10:0x14])[0]
        # Extract the username bytes from the V blob
        username_data = v_blob[username_offset: username_offset + username_length_bytes]
        # Decode the extracted bytes as UTF-16LE
        username = username_data.decode('utf-16le', errors='replace')
        return username.strip()
    except Exception as e:
        return f"Error decoding username: {e}"

def decode_f_value(f_blob):
    """
    Decode the F value binary blob.
    
    This function extracts:
      - Last login timestamp from offset 0x8 (8 bytes, little-endian FILETIME)
      - Account flags from offset 0x24 (4 bytes, little-endian)
    
    The FILETIME is converted to a human-readable date (or "Never" if zero).
    The account flags are used to determine the password policy.
    """
    try:
        # Extract the last login timestamp (8 bytes at offset 0x8)
        last_login_bytes = f_blob[8:16]
        timestamp = struct.unpack("<Q", last_login_bytes)[0]
        if timestamp == 0:
            last_login = "Never"
        else:
            last_login_dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=timestamp // 10)
            last_login = last_login_dt.strftime("%Y-%m-%d %H:%M:%S")
        # Extract account flags (4 bytes at offset 0x24)
        account_flags = struct.unpack("<I", f_blob[24:28])[0]
        password_not_required = bool(account_flags & 0x20)
        password_policy = "No Password Required" if password_not_required else "Password Required"
        return last_login, password_policy
    except Exception as e:
        return "Unknown", f"Error: {e}"

def parse_sam_hive(sam_path):
    """
    Open the SAM hive and iterate through its user account subkeys.
    
    For each user (skipping the "Names" subkey), decode the V and F values
    to extract the username, last login time, and password policy.
    """
    try:
        reg = Registry.Registry(sam_path)
    except Exception as e:
        print(f"Error opening SAM hive: {e}")
        return

    try:
        users_key = reg.open("SAM\\Domains\\Account\\Users")
    except Exception as e:
        print(f"Error accessing Users key: {e}")
        return

    for subkey in users_key.subkeys():
        if subkey.name() == "Names":
            continue 

        print(f"\nUser RID: {subkey.name()}")
        try:
            v_val = subkey.value("V").value()
            f_val = subkey.value("F").value()

            username = decode_username(v_val)
            last_login, password_policy = decode_f_value(f_val)

            print(f"Username: {username}")
            print(f"Last Login: {last_login}")
            print(f"Password Policy: {password_policy}")
        except Exception as e:
            print(f"Error processing subkey {subkey.name()}: {e}")

if __name__ == '__main__':
    sam_file = r"C:\Users\Arianne Ranada\Downloads\SAM\copySAM.hiv"  # Adjust this path as needed
    parse_sam_hive(sam_file)
