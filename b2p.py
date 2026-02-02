import sys
import argparse
import math
from PIL import Image

def encode_data(input_bin, output_png, base_img_path=None):
    # Load binary data
    with open(input_bin, 'rb') as f:
        data = f.read()
    
    # Header: 4 bytes for length + data
    payload = len(data).to_bytes(4, 'big') + data
    
    if base_img_path:
        # STEGANOGRAPHY MODE
        img = Image.open(base_img_path).convert('RGB')
        pixels = img.load()
        width, height = img.size
        
        # Check capacity (1 bit per channel, 3 channels per pixel)
        if len(payload) * 8 > width * height * 3:
            print("Error: Base image is too small for this data.")
            return

        # Convert payload to bit stream
        bit_stream = []
        for byte in payload:
            for i in range(7, -1, -1):
                bit_stream.append((byte >> i) & 1)

        bit_idx = 0
        for y in range(height):
            for x in range(width):
                if bit_idx >= len(bit_stream): break
                r, g, b = pixels[x, y]
                
                # Modify LSBs
                channels = [r, g, b]
                for i in range(3):
                    if bit_idx < len(bit_stream):
                        channels[i] = (channels[i] & ~1) | bit_stream[bit_idx]
                        bit_idx += 1
                pixels[x, y] = tuple(channels)
            if bit_idx >= len(bit_stream): break
    else:
        # STATIC MAP MODE (Square)
        side = math.ceil(math.sqrt(math.ceil(len(payload) / 3)))
        # Pad payload to fill the square
        payload += b'\x00' * ((side**2 * 3) - len(payload))
        img = Image.frombytes('RGB', (side, side), payload)

    img.save(output_png, "PNG")
    print(f"Success: Saved to {output_png}")

def decode_data(input_png, output_bin, is_stego):
    img = Image.open(input_png).convert('RGB')
    pixels = img.load()
    width, height = img.size
    
    if is_stego:
        bits = []
        for y in range(height):
            for x in range(width):
                r, g, b = pixels[x, y]
                bits.extend([r & 1, g & 1, b & 1])
        
        all_bytes = bytearray()
        for i in range(0, len(bits), 8):
            if i + 8 > len(bits): break
            byte = 0
            for bit in bits[i:i+8]:
                byte = (byte << 1) | bit
            all_bytes.append(byte)
    else:
        all_bytes = img.tobytes()

    length = int.from_bytes(all_bytes[:4], 'big')
    with open(output_bin, 'wb') as f:
        f.write(all_bytes[4:4+length])
    print(f"Success: Decoded {length} bytes to {output_bin}")

def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--encode', action='store_true')
    group.add_argument('-d', '--decode', action='store_true')
    parser.add_argument('-i', '--input', required=True)
    parser.add_argument('-o', '--output', required=True)
    parser.add_argument('-p', '--picture', help="Base image (e.g. pb.jpg)")

    args = parser.parse_args()
    if args.encode:
        encode_data(args.input, args.output, args.picture)
    else:
        decode_data(args.input, args.output, bool(args.picture))

if __name__ == "__main__":
    main()
