#Claude.ai hooked this up!
#Just put your password list in the wordlist folder and go!
#Donations: 1NfZQZAJ3s3gZdkpPAxLWwnrHKeAKesbGU

import base58
import scrypt
from Crypto.Cipher import AES
import hashlib
import binascii
from pathlib import Path
import time
import sys
import multiprocessing
from queue import Empty
from threading import Lock
import ecdsa

# Constants
ENCRYPTED_KEY = '6PnVqE7oeuw9TyDPFzGCoARcr6nMD7uEjYuez4eSpLuVmhcMNjjUfHBVG6'
TARGET_ADDRESS = '1MxomFmBQmvDgb7nH687LAhyNnBi2zEd81'
PROGRESS_LOCK = Lock()
FOUND_PASSWORD = multiprocessing.Event()

def sha256(data):
    return hashlib.sha256(data).digest()

def double_sha256(data):
    return sha256(sha256(data))

def hash160(data):
    h = hashlib.new('ripemd160')
    h.update(sha256(data))
    return h.digest()

def encode_base58check(data):
    checksum = double_sha256(data)[:4]
    return base58.b58encode(data + checksum).decode('utf-8')

def private_key_to_wif(private_key, compressed=False):
    version_key = b'\x80' + private_key
    if compressed:
        version_key += b'\x01'
    return encode_base58check(version_key)

def get_public_key(privkey, compressed=False):
    signing_key = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    point = verifying_key.pubkey.point
    
    if compressed:
        if point.y() & 1:
            return b'\x03' + point.x().to_bytes(32, byteorder='big')
        else:
            return b'\x02' + point.x().to_bytes(32, byteorder='big')
    else:
        return b'\x04' + point.x().to_bytes(32, byteorder='big') + point.y().to_bytes(32, byteorder='big')

def public_key_to_address(pub_key):
    """Convert public key to Bitcoin address"""
    hash160_bytes = hash160(pub_key)
    version_hash160_bytes = b'\x00' + hash160_bytes
    return encode_base58check(version_hash160_bytes)

def decrypt_bip38(encrypted_key, passphrase, debug=False):
    try:
        # Decode the encrypted key and get checksum
        decoded = base58.b58decode(encrypted_key)
        if debug:
            print(f"Full decoded key (hex): {decoded.hex()}")
        
        # Verify checksum
        main_part = decoded[:-4]
        checksum = decoded[-4:]
        if double_sha256(main_part)[:4] != checksum:
            raise ValueError("Invalid checksum")
        
        # Verify BIP38 prefix
        if main_part[:2] != b'\x01\x42':
            raise ValueError(f"Invalid BIP38 prefix: {main_part[:2].hex()}")
        
        # Extract components
        flagbyte = main_part[2]
        address_hash = main_part[3:7]
        encrypted_half1 = main_part[7:23]
        encrypted_half2 = main_part[23:39]

        # Check EC multiply mode and compression
        non_ec_multiply = (flagbyte & 0xc0) == 0xc0
        if not non_ec_multiply:
            raise ValueError("Only non-EC-multiply mode is supported")
        
        compressed = (flagbyte & 0x20) != 0

        # Generate key using scrypt
        derived_key = scrypt.hash(
            password=passphrase.encode('utf-8'),
            salt=address_hash,
            N=16384,
            r=8,
            p=8,
            buflen=64
        )
        
        derived_half1 = derived_key[:32]
        derived_half2 = derived_key[32:]

        # First decrypt using AES-256-ECB
        aes = AES.new(derived_half2, AES.MODE_ECB)
        decrypted_half1 = bytearray(aes.decrypt(encrypted_half1))
        decrypted_half2 = bytearray(aes.decrypt(encrypted_half2))

        # Apply XOR operations
        for i in range(16):
            decrypted_half1[i] ^= derived_half1[i]
            decrypted_half2[i] ^= derived_half1[i + 16]

        # Combine private key
        priv_key = bytes(decrypted_half1 + decrypted_half2)

        # Generate public key and address
        pub_key = get_public_key(priv_key, compressed)
        addr = public_key_to_address(pub_key)

        # Verify address hash
        calculated_hash = double_sha256(addr.encode('utf-8'))[:4]
        if calculated_hash != address_hash:
            return {'success': False, 'error': 'Address hash mismatch'}

        return {
            'success': True,
            'decrypted': priv_key.hex(),
            'wif': private_key_to_wif(priv_key, compressed),
            'passphrase': passphrase,
            'address': addr,
            'compressed': compressed
        }

    except Exception as e:
        return {'success': False, 'error': str(e)}

def worker_process(queue, progress_dict, process_id):
    attempts = 0
    while not FOUND_PASSWORD.is_set():
        try:
            passphrase = queue.get(timeout=1)
            attempts += 1
            
            if len(passphrase) >= 15:  # Only try longer passwords
                result = decrypt_bip38(ENCRYPTED_KEY, passphrase)
                if result['success'] and result['address'] == TARGET_ADDRESS:
                    print(f"\nSuccess! Found matching passphrase: {passphrase}")
                    print(f"Decrypted private key (hex): {result['decrypted']}")
                    print(f"Private key (WIF): {result['wif']}")
                    print(f"Verified Bitcoin address: {result['address']}")
                    
                    with open('success.txt', 'w') as success_file:
                        success_file.write(f"Passphrase: {passphrase}\n")
                        success_file.write(f"Decrypted private key (hex): {result['decrypted']}\n")
                        success_file.write(f"Private key (WIF): {result['wif']}\n")
                        success_file.write(f"Bitcoin address: {result['address']}\n")
                    
                    FOUND_PASSWORD.set()
                    return
            
            with PROGRESS_LOCK:
                progress_dict[process_id] = attempts
                
        except Empty:
            break
        except Exception as e:
            continue

def run_test_vector():
    """Test vector from the BIP38 specification"""
    print("Running BIP38 test vector...")
    test_vectors = [
        {
            'passphrase': 'TestingOneTwoThree',
            'encrypted': '6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg'
        },
        {
            'passphrase': 'Satoshi',
            'encrypted': '6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq'
        }
    ]
    
    for i, vector in enumerate(test_vectors, 1):
        print(f"\nTesting vector {i}:")
        result = decrypt_bip38(vector['encrypted'], vector['passphrase'])
        if result['success']:
            print("✓ SUCCESS: Decryption successful!")
            print(f"Address: {result['address']}")
            print(f"WIF: {result['wif']}")
        else:
            print(f"✗ FAIL: {result['error']}")

if __name__ == "__main__":
    # First run the test vector
    run_test_vector()
    
    # Ask user if they want to proceed with wordlist processing
    proceed = input("\nDo you want to proceed with wordlist processing? (y/n): ")
    if proceed.lower() != 'y':
        print("Exiting...")
        sys.exit(0)
    
    # Get the wordlist directory path
    wordlist_dir = Path(__file__).parent / 'wordlist'
    if not wordlist_dir.exists():
        print(f"Creating wordlist directory at: {wordlist_dir}")
        wordlist_dir.mkdir(exist_ok=True)
        print("Please place your wordlist files in this directory and run the program again.")
        sys.exit(1)
    
    # List available wordlists
    wordlists = list(wordlist_dir.glob('*'))
    if not wordlists:
        print("No wordlist files found in the wordlist directory.")
        print(f"Please add wordlist files to: {wordlist_dir}")
        sys.exit(1)
    
    print("\nAvailable wordlists:")
    for i, wordlist in enumerate(wordlists, 1):
        print(f"{i}. {wordlist.name}")
    
    # Let user select wordlist
    while True:
        try:
            selection = int(input("\nSelect wordlist number: "))
            if 1 <= selection <= len(wordlists):
                wordlist_path = wordlists[selection - 1]
                break
            print(f"Please enter a number between 1 and {len(wordlists)}")
        except ValueError:
            print("Please enter a valid number")
    
    # Get number of CPU threads
    cpu_count = multiprocessing.cpu_count()
    suggested_threads = max(1, cpu_count - 1)
    
    while True:
        try:
            num_threads = int(input(f"\nEnter number of CPU threads to use (1-{cpu_count}, recommended {suggested_threads}): "))
            if 1 <= num_threads <= cpu_count:
                break
            print(f"Please enter a number between 1 and {cpu_count}")
        except ValueError:
            print("Please enter a valid number")
    
    print(f"\nStarting BIP38 decryption attempts using wordlist: {wordlist_path}")
    
    # Initialize multiprocessing components
    password_queue = multiprocessing.Queue(maxsize=10000)
    manager = multiprocessing.Manager()
    progress_dict = manager.dict()
    
    # Start worker processes
    processes = []
    start_time = time.time()
    last_save_time = time.time()
    
    try:
        total_lines = sum(1 for _ in open(wordlist_path, 'r', encoding='utf-8', errors='ignore'))
        print(f"Starting decryption attempts with {total_lines} passwords...")
        print(f"Using {num_threads} CPU threads")
        print(f"Target Bitcoin address: {TARGET_ADDRESS}")
        
        for i in range(num_threads):
            p = multiprocessing.Process(target=worker_process, args=(password_queue, progress_dict, i))
            processes.append(p)
            p.start()
        
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                if FOUND_PASSWORD.is_set():
                    break
                password_queue.put(line.strip())
                
                if time.time() - last_save_time > 5:
                    total_attempts = sum(progress_dict.values())
                    elapsed_time = time.time() - start_time
                    rate = total_attempts / elapsed_time if elapsed_time > 0 else 0
                    percent = (total_attempts / total_lines) * 100
                    print(f"Progress: {total_attempts}/{total_lines} ({percent:.2f}%) - {rate:.2f} attempts/sec", end='\r')
                    last_save_time = time.time()
        
        for p in processes:
            p.join()
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    finally:
        for p in processes:
            if p.is_alive():
                p.terminate()
        
        total_attempts = sum(progress_dict.values())
        elapsed_time = time.time() - start_time
        print(f"\nCompleted {total_attempts} attempts in {elapsed_time:.2f} seconds")
        print(f"Average rate: {total_attempts/elapsed_time:.2f} attempts/sec")
