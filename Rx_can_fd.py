import can

from lutz_functions import *
from lutz_algos import *

from ascon import *

def receive_can_fd_messages(channel="can1"):
    """
    Receive CAN FD messages from a specified interface.
    
    Parameters:
    - interface (str): CAN interface to listen on (e.g. "can1").
    """

    if os.path.exists("./Data/decryption_times.csv"):
        writeheaderFlag = False
    else:
        writeheaderFlag = True

    with open("./Data/decryption_times.csv", 'a') as decryption_times_writer:
        if writeheaderFlag:
            decryption_times_writer.write("Algorithm, Key Size, Time\n")
        
        try:
            # Open CAN bus for receiving
            bus = can.interface.Bus(channel=channel, interface="socketcan", fd=True)
            key_128 = b'5\x8d~\x96\xec^\xae\xca\x05\x0c\x02`*.\xf1o'  # Random 128-bit key (16 bytes)
            key_168 = b'\xa7\x84$\xae\x86z}\x0cI\xe3kSy\xe1\xa8\xe3:*H\xc8E'  # Random 168-bit key (21 bytes)
            key_192 = b"}\x94\x7f\xc7\xa8\xd39\x19\xc4,\xeb'\xf0\xf9\xba\xbb\xc6\xe0c\x97\xbbT\xa2/" # Random 192-bit key (24 btyes)
            key_256 = b"0\xa1O\xe2\xf9K|\xeb\xe4\x18\xa2:\xb3\x92\xc0\x88dSq\xfb2\xc5G\xff'\x87\xec\x94\x11\x8a-\xf3" # Random 256-bit key (32 bytes)
            key_320 = b'\xec$[\x94th.\xd3\x8b\x94\x03\x92\xc7\xbe\x14\r\xd8$i\xae\x82\xbb*\x9dc\x94pj\xeaS\xb2s\x81\x99bE\x0e\xfb\xdaN' # Random 320-bit key (40 bytes)
            key_448 = b'F\x0e)S\x00\xf5\xf9\xba\xaf\xca\x8dgX7YLN\xd1\xa3q\x1dr;\xb9\xb1\t\xcf\xdc\xca \x88\xdbUT\xac\x12*\xf53|\xd4\x05\xc3^\xf6\xbb\xfb\x83\xe8%\xd7\x1e\x14\x92\x15f' # Random 448-bit key (56 bytes)
            IV_len = 16
            
            print(f"Listening for CAN FD messages on {channel}...")            
            
            # Removing file used for comparison to start fresh
            if os.path.exists("comparison_file.txt"):
                os.remove("comparison_file.txt")

            with open("comparison_file.txt", 'wb'):
                pass  # Do nothing, just create/clear the file

            while True:
                # Receive a message
                encrypted_msg = bus.recv()  # This will block until a message is received
                
                if encrypted_msg.arbitration_id == 0xA or encrypted_msg.arbitration_id == 0xD:
                    bus.shutdown()
                    set_down_physical_can("can1")
                    return encrypted_msg.arbitration_id
                
                match encrypted_msg.arbitration_id:
                    case 0xC:
                        decrypted_msg = encrypted_msg.data
                        append_to_file("comparison_file.txt", decrypted_msg)
                        continue
                    
                    # AES CBC
                    case 0xAEC128:
                        IV_len = 16
                        start_decrypt = time.perf_counter()
                        decrypted_msg = decrypt_AES_CBC(encrypted_msg.data, key_128, iv_length=IV_len)
                        decryption_time_elapsed = time.perf_counter() - start_decrypt
                        decryption_times_writer.write(f"AES_CBC,128,{str(decryption_time_elapsed)}\n")
                    case 0xAEC192:
                        IV_len = 16
                        start_decrypt = time.perf_counter()
                        decrypted_msg = decrypt_AES_CBC(encrypted_msg.data, key_192, iv_length=IV_len)
                        decryption_time_elapsed = time.perf_counter() - start_decrypt
                        decryption_times_writer.write(f"AES_CBC,192,{str(decryption_time_elapsed)}\n")
                    case 0xAEC256:
                        IV_len = 16
                        start_decrypt = time.perf_counter()
                        decrypted_msg = decrypt_AES_CBC(encrypted_msg.data, key_256, iv_length=IV_len)
                        decryption_time_elapsed = time.perf_counter() - start_decrypt
                        decryption_times_writer.write(f"AES_CBC,256,{str(decryption_time_elapsed)}\n")
                        
                    # AES GCM
                    case 0xAE128:
                        start_decrypt = time.perf_counter()
                        decrypted_msg = decrypt_AES_GCM(encrypted_msg.data, key_128)
                        decryption_time_elapsed = time.perf_counter() - start_decrypt
                        decryption_times_writer.write(f"AES_GCM,128,{str(decryption_time_elapsed)}\n")
                    case 0xAE192:
                        start_decrypt = time.perf_counter()
                        decrypted_msg = decrypt_AES_GCM(encrypted_msg.data, key_192)
                        decryption_time_elapsed = time.perf_counter() - start_decrypt
                        decryption_times_writer.write(f"AES_GCM,192,{str(decryption_time_elapsed)}\n")
                    case 0xAE256:
                        start_decrypt = time.perf_counter()
                        decrypted_msg = decrypt_AES_GCM(encrypted_msg.data, key_256)  
                        decryption_time_elapsed = time.perf_counter() - start_decrypt
                        decryption_times_writer.write(f"AES_GCM,256,{str(decryption_time_elapsed)}\n")
                        
                    # Blowfish CBC
                    case 0xBF128:
                        IV_len = 8
                        start_decrypt = time.perf_counter()
                        decrypted_msg = decrypt_blowfish(encrypted_msg.data, key_128, IV_len)
                        decryption_time_elapsed = time.perf_counter() - start_decrypt
                        decryption_times_writer.write(f"Blowfish,128,{str(decryption_time_elapsed)}\n")
                    case 0xBF256:
                        IV_len = 8
                        start_decrypt = time.perf_counter()
                        decrypted_msg = decrypt_blowfish(encrypted_msg.data, key_256, IV_len)
                        decryption_time_elapsed = time.perf_counter() - start_decrypt
                        decryption_times_writer.write(f"Blowfish,256,{str(decryption_time_elapsed)}\n")
                    case 0xBF320:
                        IV_len = 8
                        start_decrypt = time.perf_counter()
                        decrypted_msg = decrypt_blowfish(encrypted_msg.data, key_320, IV_len) 
                        decryption_time_elapsed = time.perf_counter() - start_decrypt
                        decryption_times_writer.write(f"Blowfish,320,{str(decryption_time_elapsed)}\n")
                    case 0xBF448:
                        IV_len = 8
                        start_decrypt = time.perf_counter()
                        decrypted_msg = decrypt_blowfish(encrypted_msg.data, key_448, IV_len) 
                        decryption_time_elapsed = time.perf_counter() - start_decrypt
                        decryption_times_writer.write(f"Blowfish,448,{str(decryption_time_elapsed)}\n")
                        
                    # Camellia
                    case 0xCA128:
                        IV_len = 16
                        start_decrypt = time.perf_counter()
                        decrypted_msg = decrypt_camellia(encrypted_msg.data, key_128, IV_len)
                        decryption_time_elapsed = time.perf_counter() - start_decrypt
                        decryption_times_writer.write(f"Camellia,128,{str(decryption_time_elapsed)}\n")
                    case 0xCA192:
                        IV_len = 16
                        start_decrypt = time.perf_counter()
                        decrypted_msg = decrypt_camellia(encrypted_msg.data, key_192, IV_len)
                        decryption_time_elapsed = time.perf_counter() - start_decrypt
                        decryption_times_writer.write(f"Camellia,192,{str(decryption_time_elapsed)}\n")
                    case 0xCA256:
                        IV_len = 16
                        start_decrypt = time.perf_counter()
                        decrypted_msg = decrypt_camellia(encrypted_msg.data, key_256, IV_len)
                        decryption_time_elapsed = time.perf_counter() - start_decrypt
                        decryption_times_writer.write(f"Camellia,256,{str(decryption_time_elapsed)}\n")
                        
                    # 3DES
                    case 0xDE128:
                        IV_len = 8
                        start_decrypt = time.perf_counter()
                        decrypted_msg = decrypt_3DES(encrypted_msg.data, key_128, IV_len)
                        decryption_time_elapsed = time.perf_counter() - start_decrypt
                        decryption_times_writer.write(f"3DES,128,{str(decryption_time_elapsed)}\n")
                    case 0xDE192:
                        IV_len = 8
                        start_decrypt = time.perf_counter()
                        decrypted_msg = decrypt_3DES(encrypted_msg.data, key_192, IV_len)
                        decryption_time_elapsed = time.perf_counter() - start_decrypt
                        decryption_times_writer.write(f"3DES,192,{str(decryption_time_elapsed)}\n")
                        
                    # ChaCha20
                    case 0xCC20:
                        full_nonce_len = 16
                        start_decrypt = time.perf_counter()
                        decrypted_msg = decrypt_chacha20(encrypted_msg.data, key_256, full_nonce_len)
                        decryption_time_elapsed = time.perf_counter() - start_decrypt
                        decryption_times_writer.write(f"ChaCha20,256,{str(decryption_time_elapsed)}\n")
                        
                    # Ascon-128
                    case 0xAC128:
                        start_decrypt = time.perf_counter()
                        decrypted_msg = decrypt_ascon128(encrypted_msg.data, key_128, associated_data= b'')
                        decryption_time_elapsed = time.perf_counter() - start_decrypt
                        decryption_times_writer.write(f"Ascon-128,128,{str(decryption_time_elapsed)}\n")
                        
                        
                    case 0xF:
                        comparison_file = "comparison_file.txt"
                        truth_files = ["random_bytes_500KB.txt", "random_bytes_1MB.txt", "random_bytes_2MB.txt", "tester.txt"]
                        
                        if file_matches_any(comparison_file, truth_files):  
                            print("FILES MATCH!!!")
                        else:
                            print("FILES DO NOT MATCH!!!")
                            
                        # Removing file used for comparison to start fresh
                        if os.path.exists("comparison_file.txt"):
                            os.remove("comparison_file.txt")
                            with open("comparison_file.txt", 'wb'):
                                pass  # Do nothing, just create/clear the file
                        continue
                            
                append_to_file("comparison_file.txt", decrypted_msg)
                
                    

        
        except KeyboardInterrupt:
            print("Exiting...")
        
        finally:            
            bus.shutdown()
            set_down_physical_can("can1")
            
# Sets up CAN to some default so that it can wait for the first message
# signifying the start of testing
interface = "can1"

setup_physical_can_fd(interface)
receive_can_fd_messages(interface)
print("Initialization Done!")

while True:
    result = subprocess.run(
        ["ip", "link", "show", interface],
        capture_output=True,
        text=True,
        check=True
    )
    # Check if "state DOWN" is in the output
    if "state DOWN" in result.stdout:
        continue
    else:
        break

# Start listening on can1 
# Continues to loop until the 0xDONE arb_id has been received signifying all
# testing is done
# Removing file used for decryption timing to start fresh
if os.path.exists("./Data/decryption_times.csv"):
    os.remove("./Data/decryption_times.csv")
    
arb_id = 0x0
while arb_id != 0xD:
    
    arb_id = receive_can_fd_messages(interface)
    
    if arb_id == 0xD:
        print("Testing complete!")
        break
    
    # Continually waits for can1 to be back online before trying to receive
    # messages again
    print("Checking connectivity...")
    while True:
        result = subprocess.run(
            ["ip", "link", "show", interface],
            capture_output=True,
            text=True,
            check=True
        )
        # Check if "state DOWN" is in the output
        if "state DOWN" in result.stdout:
            continue
        else:
            print("Connectivity verified!")
            print("Starting next test...\n")
            break
    