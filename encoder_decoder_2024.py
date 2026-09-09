"""
Shaikh Zaki | 2024
Encoder / Decoder Tool

A small command-line tool that can encode and decode text in three
common formats: Base64, Hexadecimal and URL encoding.

It can also try to GUESS which format a given piece of text is in.
This is useful in security work because tools, tokens, and passwords
are often stored/transmitted in one of these encodings.

Note--> Encoding is NOT encryption. Anyone can decode it. It's just a
different way of representing the same data (e.g. so it can safely
travel through a URL or a text field).
"""

import base64
import urllib.parse
import re


#ENCODING FUNCTIONS 

def encode_base64(text):
    # base64 works on bytes not strings  so we convert first
    return base64.b64encode(text.encode()).decode()

def decode_base64(text):
    return base64.b64decode(text).decode()


def encode_hex(text):
    return text.encode().hex()

def decode_hex(text):
    return bytes.fromhex(text).decode()


def encode_url(text):
    return urllib.parse.quote(text)

def decode_url(text):
    return urllib.parse.unquote(text)


# FORMAT DETECTION

def detect_format(text):
    """
    Very simple guesser. Checks the text against patterns typical
    of each encoding and returns the most likely one.
    """
    text = text.strip()

    # URL encoding always has %XX sequences
    if re.search(r"%[0-9A-Fa-f]{2}", text):
        return "URL Encoding"

    # Hex only uses 0-9 and a-f, and has an even number of characters
    if re.fullmatch(r"[0-9A-Fa-f]+", text) and len(text) % 2 == 0:
        return "Hexadecimal"

    # Base64 uses A-Z, a-z, 0-9, +, /, and = for padding
    # length is also usually a multiple of 4
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", text) and len(text) % 4 == 0:
        return "Base64"

    return "Unknown (looks like plain text)"


# SIMPLE MENU 

def main():
    print("=== Encoder / Decoder Tool ===")
    print("1. Encode text")
    print("2. Decode text")
    print("3. Detect encoding format")
    choice = input("Choose an option (1/2/3): ").strip()

    if choice == "1":
        text = input("Enter text to encode: ")
        print("\nResults:")
        print("Base64 :", encode_base64(text))
        print("Hex    :", encode_hex(text))
        print("URL    :", encode_url(text))

    elif choice == "2":
        fmt = input("Which format is it? (base64/hex/url): ").strip().lower()
        text = input("Enter text to decode: ")
        try:
            if fmt == "base64":
                print("Decoded:", decode_base64(text))
            elif fmt == "hex":
                print("Decoded:", decode_hex(text))
            elif fmt == "url":
                print("Decoded:", decode_url(text))
            else:
                print("Unknown format entered.")
        except Exception as e:
            print("Could not decode. Error:", e)

    elif choice == "3":
        text = input("Enter text to detect: ")
        print("Detected format:", detect_format(text))

    else:
        print("Invalid choice.")


if __name__ == "__main__":
    main()
