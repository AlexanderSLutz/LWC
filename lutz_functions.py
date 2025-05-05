import subprocess
import os
import can
import time
import psutil
from datetime import datetime


def send_message(bus, msg):
    """
    Repeatadly trys to send message and only moves on once that message has been sent
    """
    sent = False
    while not sent:
        try:
            bus.send(msg,1)
            sent = True  # Message sent successfully
        except can.CanError as e:
            if "Transmit buffer full" in str(e):
                time.sleep(0.001)
                continue  # Retry immediately
            else:
                print(f"Failed to send message: {e}")
                break  # Exit on other errors


def can_fd_throughput(payload_bytes, nominal_bitrate, data_bitrate, extended_id=True):
    # Estimate arbitration bits
    arbitration_bits = 67 if extended_id else 47

    # CRC depends on payload size
    crc_bits = 21 if payload_bytes > 16 else 17

    data_bits = (payload_bytes * 8) + crc_bits

    arbitration_time = arbitration_bits / nominal_bitrate
    data_time = data_bits / data_bitrate

    total_time = arbitration_time + data_time

    throughput_bps = (payload_bytes * 8) / total_time
    throughput_Bps = payload_bytes / total_time


    return total_time


def setup_physical_can_fd(interface="can0", bitrate=1000000, dbitrate=1000000):
    """
    Set up a physical CAN FD interface on Linux.
    
    Parameters:
    - interface (str): Name of the CAN FD interface (e.g., "can0").
    - bitrate (int): Nominal bitrate (e.g., 500000).
    - dbitrate (int): Data-phase bitrate for CAN FD (e.g., 2000000).
    """
    try:
        # Bring down the interface (if it's already up)
        result = subprocess.run(
            ["ip", "link", "show", interface],
            capture_output=True,
            text=True,
            check=True
        )
        
        # Check if "state UP" is in the output
        if "state UP" in result.stdout:
            subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)

        # Set up CAN FD with specified bitrates
        subprocess.run([
            "sudo", "ip", "link", "set", interface, "type", "can", "bitrate", str(bitrate),
            "dbitrate", str(dbitrate), "restart-ms", "1000", "berr-reporting", "on", "fd", "on",
            "fd-non-iso", "on"
        ], check=True)
        
        # Bring up the interface
        subprocess.run(["sudo", "ifconfig", interface, "txqueuelen", "65536"], check=True)

        # Bring up the interface
        subprocess.run(["sudo", "ip", "link", "set", "up", interface], check=True)

        print(f"CAN FD interface {interface} configured successfully!")

    except subprocess.CalledProcessError as e:
        print(f"Error setting up CAN FD: {e}")
        
def set_down_physical_can(interface):
    """
    Set down a physical CAN FD interface on Linux.
    
    Parameters:
    - interface (str): Name of the CAN FD interface (e.g., "can0").
    """
    try:
        # Bring down the interface (if it's already up)
        subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)

        print(f"CAN FD interface {interface} set down successfully!")

    except subprocess.CalledProcessError as e:
        print(f"Error setting down physical CAN: {e}")
        
        

def log_python_process_cpu(f, key_length: str, algorithm_name: str):
    """
    Logs system CPU usage along with algorithm name and key length.
    
    Parameters:
    - f: A file-like writer object
    - key_length: The cryptographic key length (e.g., 128)
    - algorithm_name: The name of the algorithm used (e.g., 'AES', 'ASCON')
    """
    cpu_percent = psutil.cpu_percent(interval=0)  # Get instantaneous CPU usage
    f.write(f"{algorithm_name},{key_length},{cpu_percent:.2f}\n")


def random_byte_array(n: int) -> bytes:
    """Generate a random byte array of length n."""
    return os.urandom(n)

def create_random_CAN_data(filename: str, numBytes:int):
    """Generate n random bytes and write them to a file."""
    with open(filename, "wb") as file:
        file.write(random_byte_array(numBytes))
        
def read_file_in_chunks(filename: str, chunk_size: int):
    """
    Read a file in chunks of specified byte size. 
    Only puts into memory the specified chunk size, 
    therfore allows for large files to be read
    """
    with open(filename, "rb") as file:
        while chunk := file.read(chunk_size):
            yield chunk




def append_to_file(file_path: str, byte_data: bytes):
    with open(file_path, 'ab') as f:
        f.write(byte_data)  # Adds a newline after each entry
        
def file_matches_any(target_file: str, other_files: list[str]) -> bool:
    if not os.path.exists(target_file):
        raise FileNotFoundError(f"{target_file} does not exist.")

    with open(target_file, 'rb') as f1:
        target_data = f1.read()

    for file_path in other_files:
        if not os.path.exists(file_path):
            continue  # Skip missing files

        with open(file_path, 'rb') as f2:
            if target_data == f2.read():
                return True  # Match found

    return False  # No matches found


def compare_truth_2_sent_file_data(bus):
    # Sends can message with arb_id 0xF to signal time to file compare
    msg = can.Message(arbitration_id=0xF,  # CAN ID
                        data= os.urandom(64) ,  # Data (max 8 bytes for standard CAN)
                        is_fd=True,         # Set to True for extended CAN ID
                        is_extended_id=True)  # Allows extended arb id
    send_message(bus, msg)
    
def strip_nulls_if_two_or_more(data: bytes) -> bytes:
    """
    Strips trailing b'\x00' bytes from the end of the input only if there are
    2 or more in a row. Otherwise, returns the original data.
    """
    
    null_count = 0
    for b in reversed(data):
        if b == 0:
            null_count += 1
        else:
            break

    if null_count >= 2:
        return data[:-null_count]
    else:
        return data

if __name__ == '__main__':
    print("testing")

    # set_down_physical_can("can0")
    # set_down_physical_can("can1")
    # setup_physical_can_fd(interface="can0")
    # setup_physical_can_fd(interface="can1")
    
    # kiloByte = 1024
    # megaByte = kiloByte * 1024 # Number of bytes in a megabyte
    # gigaByte = megaByte * 1024
    # create_random_CAN_data("random_bytes.txt", int(megaByte * 0.5))
    # create_random_CAN_data("random_bytes_1MB.txt", megaByte)
    # create_random_CAN_data("random_bytes_2MB.txt", megaByte * 2)
    # create_random_CAN_data("random_bytes_8MB.txt", megaByte * 8)
    # create_random_CAN_data("tester.txt", 10000 * 36)
    # create_random_CAN_data("random_bytes_500KB.txt",500004)
    create_random_CAN_data("random_bytes_1MB.txt",1000080)
    # create_random_CAN_data("random_bytes_2MB.txt",2000016)

    # for chunk in read_file_in_chunks("random_bytes.txt", 64):
    #     print(chunk)

    # print(os.urandom(int(64/8)))
    # print(os.urandom(int(112/8)))
    # print(os.urandom(int(168/8)))
    # print(os.urandom(24))
    # print(os.urandom(40))
    # print(os.urandom(56))

    # can_message = b"\x01\x02\x03\x04\x05\x06\x07\x08" * 8  # 64-byte CAN data
    # key = os.urandom(32)  # Generate a random 256-bit key

    # encrypted_can_message = encrypt_can_message(can_message, key)
    # print(f"Encrypted CAN Message: {encrypted_can_message} \nWith length: {len(encrypted_can_message)}")

    # decrypted_can_message = decrypt_can_message(encrypted_can_message, key)
    # print(f"Decrypted CAN Message: {decrypted_can_message}")