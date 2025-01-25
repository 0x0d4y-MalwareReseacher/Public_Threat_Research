import pefile
import binascii
import arc4
import json
import hashlib

def decrypt_rc4(key, encrypt_data):
    arc4_cipher = arc4.ARC4(key)
    return arc4_cipher.decrypt(encrypt_data)

def extract_pe_section(file_path, section_name, key_size, enc_data):
    try:
        # Load the PE file
        pe = pefile.PE(file_path)

        # Search for the desired section
        for section in pe.sections:
            if section.Name.decode().rstrip('\x00') == section_name:
                # Extract raw data
                raw_data = section.get_data()

                # Extract the key and the encrypted data
                key_data = raw_data[:key_size]
                remaining_data = raw_data[key_size:key_size + enc_data]

                # Convert to hexadecimal
                key_hex = binascii.hexlify(key_data).decode('utf-8')
                remaining_hex = binascii.hexlify(remaining_data).decode('utf-8')

                # Decrypt using RC4
                key = binascii.unhexlify(key_hex)
                encrypted_data = binascii.unhexlify(remaining_hex)
                decrypted_data = decrypt_rc4(key, encrypted_data)

                # Remove unwanted characters
                decrypted_data_filtered = [part.decode('latin-1').replace('\u000e', '').replace('\u000f', '').replace('\u0006', '').replace('\u0010', '').replace('\u001e\u0002', '').replace('\u0013', '') for part in decrypted_data.split(b'\x00') if part]

                # Prepare the result dictionary
                result_dict = {
                    "Title": "IcedID Config Extraction",
                    "Binary Name": pe_file_path,
                    "SHA256 Hash": hashlib.sha256(raw_data).hexdigest(),
                    "Hex RC4 Key": key_hex,
                    "Hex Encrypted Data": remaining_hex,
                    "Decrypted Data": decrypted_data_filtered
                }

                return result_dict

        else:
            return {"error": f"Section '{section_name}' not found in the PE file."}

    except Exception as e:
        return {"error": f"Error processing the PE file: {e}"}

# Static information
section_name = ".data"
key_size = 8
enc_data = 248

# main loop
while True:
    try:
        # Prompt the user for the PE file path
        pe_file_path = input("\n[+] Enter the IcedID file path (Ctrl+C to exit): ")

        # Call the function to extract section data
        result = extract_pe_section(pe_file_path, section_name, key_size, enc_data)

        # Check for errors in the result
        if "error" in result:
            print(f"\n[-] {result['error']} [-]")
        else:
            # Print the result as JSON with improved formatting
            json_result = json.dumps(result, indent=4, ensure_ascii=False)
            print(f"\n[+] Result in JSON format:\n{json_result}")

            # Save the result to a JSON file
            output_file_path = f"{pe_file_path}-output-conf-extract.json"
            with open(output_file_path, 'w') as json_file:
                json.dump(result, json_file, indent=4, ensure_ascii=False)

            print(f"\n[+] Result saved to '{output_file_path}'.")

    except KeyboardInterrupt:
        print("\n[!] Program terminated by user (Ctrl+C). Goodbye!")
        break
    except Exception as e:
        print(f"\n[-] An error occurred: {e} [-]")
