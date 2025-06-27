from django.shortcuts import render, redirect
from django.core.files.storage import default_storage
from django.conf import settings
import stepic
from PIL import Image
import io
import os
import cv2
import numpy as np
from django.contrib import messages
import base64
import binascii
from django.shortcuts import render
import wave
import struct
from django.http import HttpResponse
from io import BytesIO
import subprocess
import shutil
from django.core.files.uploadedfile import InMemoryUploadedFile
import tempfile

def index(request):
    return render(request, 'index.html')



# Hardcoded User Credentials
USER_CREDENTIALS = {
    "user1": "password123",
    "admin": "adminpass",
    "guest": "guest123"
}

def login_view(request):
    """ Handles user login with hardcoded credentials """
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        if username in USER_CREDENTIALS and USER_CREDENTIALS[username] == password:
            request.session["user"] = username  # Store session
            return redirect("index")  # Redirect to index
        else:
            messages.error(request, "❌ Invalid username or password")
    return render(request, "login.html")

def logout_view(request):
    """ Logs out the user by clearing session data """
    request.session.flush()  # Clears all session data
    return redirect("login")  # Redirect to login page


# ========================== IMAGE STEGANOGRAPHY ==========================

def image_steganography_selection(request):
    return render(request, 'image_steganography_selection.html')

def hide_text_in_image(image, text, password):
    """ Encode text into an image using stepic with password protection """
    data = f"{password}:{text}".encode('utf-8')
    return stepic.encode(image, data)

def encryption_view(request):
    """ Handles text encryption inside an image and returns it as a downloadable file,
        while also saving it to a fixed location with '_en' suffix.
    """
    if request.method == 'POST' and request.FILES.get('image'):
        text = request.POST.get('text', '')
        password = request.POST.get('password', '')
        image_file = request.FILES['image']

        try:
            image = Image.open(image_file)
            if image.mode != 'RGBA':
                image = image.convert('RGBA')

            # Encrypt the text into the image
            new_image = hide_text_in_image(image, text, password)

            # Create output filename
            original_name = os.path.splitext(image_file.name)[0]
            output_filename = original_name + '_en.png'

            # Save to specified directory
            save_dir = r"C:\\Users\\M Taha Z Shaikh\\OneDrive\\Desktop\\Stegano001\\stegano_project\\encrypted content\\enc_image"
            os.makedirs(save_dir, exist_ok=True)
            save_path = os.path.join(save_dir, output_filename)

            new_image.save(save_path, format='PNG')

            # Also return as downloadable response
            buffer = BytesIO()
            new_image.save(buffer, format='PNG')
            buffer.seek(0)

            response = HttpResponse(buffer, content_type='image/png')
            response['Content-Disposition'] = f'attachment; filename="{output_filename}"'
            return response

        except Exception as e:
            return render(request, 'encryption.html', {
                'message': f"\u274c Error: {str(e)}"
            })

    return render(request, 'encryption.html')

def decryption_view(request):
    """ Handles text extraction from an encrypted image with password verification """
    text = ''
    error = ''

    if request.method == 'POST' and request.FILES.get('image'):
        password = request.POST.get('password', '')
        try:
            image_file = request.FILES['image']
            image = Image.open(image_file)
            if image.mode != 'RGBA':
                image = image.convert('RGBA')

            extracted_text = extract_text_from_image(image)
            if extracted_text.startswith(f"{password}:"):
                text = extracted_text[len(password) + 1:]
            else:
                error = "\u274c Incorrect password. Cannot retrieve hidden text."
        except Exception as e:
            error = f"\u274c Error: {str(e)}"

    return render(request, 'decryption.html', {'text': text, 'error': error})

def extract_text_from_image(image):
    """ Extract hidden text from an image """
    try:
        data = stepic.decode(image)
        return data.decode('utf-8') if isinstance(data, bytes) else data
    except Exception:
        return "\u274c Error extracting text."




# ========================== AUDIO STEGANOGRAPHY ==========================

def audio_steganography_selection(request):
    return render(request, 'audio_steganography_selection.html')

def audio_encrypt(request):
    print("\U0001f512 Received request to encrypt audio")  # Debug
    message = ''
    encrypted_audio_url = None

    if request.method == 'POST' and request.FILES.get('audio'):
        text = request.POST.get('message', '')
        password = request.POST.get('password', '')
        audio_file = request.FILES['audio']

        print(f"\U0001f4e5 Uploaded audio file: {audio_file.name}")
        print(f"\U0001f4dd Message to encode: {text}")
        print(f"\U0001f511 Password received: {password}")

        if not text or not password:
            message = "❌ Both message and password are required."
        else:
            try:
                # Combine password and message
                combined_message = f"{password}::{text}"

                # Save original audio temporarily
                temp_audio_path = default_storage.save(f'audio_temp/{audio_file.name}', audio_file)
                input_path = os.path.join(settings.MEDIA_ROOT, temp_audio_path)
                print(f"✅ Saved audio to: {input_path}")

                # Define permanent save directory and file name
                save_dir = r"C:\\Users\\M Taha Z Shaikh\\OneDrive\\Desktop\\Stegano001\\stegano_project\\encrypted content\\enc_audio"
                os.makedirs(save_dir, exist_ok=True)
                base_name = os.path.splitext(audio_file.name)[0]
                output_name = f"{base_name}_en.wav"
                output_path = os.path.join(save_dir, output_name)

                # Encrypt the combined message
                success = hide_text_in_audio(input_path, output_path, combined_message)

                if success:
                    message = "✅ Audio encrypted successfully with password!"
                    encrypted_audio_url = output_path  # Local path, not media URL
                    print(f"🔒 Encrypted audio saved to: {output_path}")
                else:
                    message = "❌ Failed to encrypt the audio."
                    print("⚠️ Encryption function returned failure.")

            except Exception as e:
                message = f"❌ Error: {str(e)}"
                print(f"💥 Exception occurred: {e}")

    return render(request, 'audio_steganography.html', {
        'message': message,
        'audio_file': encrypted_audio_url,
    })

def audio_decrypt(request):
    print("\U0001f513 Received request to decrypt audio")  # Debug
    decrypted_message = ''
    error = ''

    if request.method == 'POST' and request.FILES.get('audio'):
        password = request.POST.get('password', '').strip()
        print(f"\U0001f511 Password entered: {password}")

        try:
            audio_file = request.FILES['audio']
            print(f"\U0001f4e5 Uploaded audio file: {audio_file.name}")

            # Save the audio temporarily
            audio_path = default_storage.save(f'audio_temp/{audio_file.name}', audio_file)
            input_path = os.path.join(settings.MEDIA_ROOT, audio_path)
            print(f"\U0001f4c1 Saved audio file at: {input_path}")

            # Extract hidden content
            extracted = extract_text_from_audio(input_path)

            if not extracted:
                error = "❌ No hidden message found in the audio."
                print("🔍 No message decoded.")
            else:
                # Expecting format: password::message
                if "::" in extracted:
                    extracted_password, actual_message = extracted.split("::", 1)

                    if password == extracted_password:
                        decrypted_message = actual_message
                        print(f"✅ Password match. Message extracted: {actual_message}")
                    else:
                        error = "❌ Incorrect password."
                        print("⚠️ Password mismatch.")
                else:
                    error = "❌ Invalid format of embedded message."
                    print("⚠️ Embedded message format invalid.")

        except Exception as e:
            error = f"❌ Error: {str(e)}"
            print(f"💥 Exception during decryption: {e}")

    return render(request, 'audio_decryption.html', {
        'decrypted_message': decrypted_message,
        'error': error
    })

def hide_text_in_audio(input_path, output_path, message):
    try:
        print("🔧 Hiding text in audio...")  # Debug
        message += "###"  # End marker
        binary_message = ''.join(format(ord(i), '08b') for i in message)

        with wave.open(input_path, mode='rb') as audio:
            frame_bytes = bytearray(list(audio.readframes(audio.getnframes())))
            print(f"🧱 Total audio bytes: {len(frame_bytes)}, Bits to embed: {len(binary_message)}")

            if len(binary_message) > len(frame_bytes):
                print("❌ Message too large to embed in audio.")
                return False

            for i in range(len(binary_message)):
                frame_bytes[i] = (frame_bytes[i] & 254) | int(binary_message[i])

            with wave.open(output_path, 'wb') as modified_audio:
                modified_audio.setparams(audio.getparams())
                modified_audio.writeframes(bytes(frame_bytes))

        print("✅ Message embedded successfully.")
        return True
    except Exception as e:
        print(f"💥 Audio encryption error: {e}")
        return False

def extract_text_from_audio(input_path):
    try:
        print("🧪 Extracting text from audio...")  # Debug
        with wave.open(input_path, mode='rb') as audio:
            frame_bytes = bytearray(list(audio.readframes(audio.getnframes())))

        extracted_bits = [str(byte & 1) for byte in frame_bytes]
        binary_string = ''.join(extracted_bits)

        decoded_chars = []
        for i in range(0, len(binary_string), 8):
            byte = binary_string[i:i+8]
            decoded_chars.append(chr(int(byte, 2)))
            if ''.join(decoded_chars).endswith("###"):
                message = ''.join(decoded_chars[:-3])
                print(f"✅ Extracted message: {message}")
                return message

        print("❌ End marker not found in audio.")
        return None
    except Exception as e:
        print(f"💥 Audio decryption error: {e}")
        return None


# ========================== VIDEO STEGANOGRAPHY ==========================

def video_steganography_selection(request):
    """Renders the video steganography selection page"""
    return render(request, 'video_steganography_selection.html')


def video_text_encrypt(request):
    """Encrypts (hides) secret text into the first frame of the uploaded video using LSB steganography"""
    if request.method == 'POST' and request.FILES.get('video') and request.POST.get('secret_text'):
        video_file = request.FILES['video']
        secret_text = request.POST['secret_text']

        temp_dir = tempfile.mkdtemp()
        video_path = os.path.join(temp_dir, video_file.name)

        with open(video_path, 'wb+') as f:
            for chunk in video_file.chunks():
                f.write(chunk)

        cap = cv2.VideoCapture(video_path)
        ret, frame = cap.read()
        cap.release()

        if not ret:
            shutil.rmtree(temp_dir)
            return render(request, 'video_encryption.html', {
                'message': '❌ Failed to read the video.'
            })

        # Convert text to binary with a delimiter
        binary_text = ''.join(format(ord(c), '08b') for c in secret_text) + '1111111111111110'
        flat_frame = frame.flatten()

        if len(binary_text) > len(flat_frame):
            shutil.rmtree(temp_dir)
            return render(request, 'video_encryption.html', {
                'message': '❌ Text too long to hide in this frame.'
            })

        # Embed binary data in LSBs
        for i in range(len(binary_text)):
            flat_frame[i] = (flat_frame[i] & 254) | int(binary_text[i])

        stego_frame = flat_frame.reshape(frame.shape)

        # Save to temp .avi using FFV1 codec (lossless)
        height, width = stego_frame.shape[:2]
        fourcc = cv2.VideoWriter_fourcc(*'FFV1')
        fps = 25

        original_name = os.path.splitext(video_file.name)[0]
        output_filename = original_name + "_en.avi"
        temp_output_path = os.path.join(temp_dir, output_filename)

        out = cv2.VideoWriter(temp_output_path, fourcc, fps, (width, height))
        out.write(stego_frame)

        # Append remaining frames
        cap = cv2.VideoCapture(video_path)
        cap.read()  # Skip first frame
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            out.write(frame)
        cap.release()
        out.release()

        # Final save path
        final_save_dir = r"C:\Users\M Taha Z Shaikh\OneDrive\Desktop\Stegano001\stegano_project\encrypted content\enc_video"
        os.makedirs(final_save_dir, exist_ok=True)
        final_output_path = os.path.join(final_save_dir, output_filename)

        shutil.move(temp_output_path, final_output_path)

        # Read and encode for frontend display/download
        with open(final_output_path, 'rb') as f:
            video_data = f.read()
        shutil.rmtree(temp_dir)

        encoded_video = base64.b64encode(video_data).decode('utf-8')
        return render(request, 'video_encryption.html', {
            'video_base64': encoded_video,
            'filename': output_filename,
            'message': '✅ Text successfully hidden in video!'
        })

    return render(request, 'video_encryption.html')


def video_text_decrypt(request):
    """Decrypts (extracts) hidden text from the first frame of the uploaded video using LSB steganography"""
    if request.method == 'POST' and request.FILES.get('video'):
        video_file = request.FILES['video']

        # Save uploaded video to temporary directory
        temp_dir = tempfile.mkdtemp()
        video_path = os.path.join(temp_dir, video_file.name)

        with open(video_path, 'wb+') as f:
            for chunk in video_file.chunks():
                f.write(chunk)

        cap = cv2.VideoCapture(video_path)
        ret, frame = cap.read()
        cap.release()

        if not ret:
            shutil.rmtree(temp_dir)
            return render(request, 'video_decryption.html', {
                'message': '❌ Failed to read the video.'
            })

        flat_frame = frame.flatten()

        # Extract LSBs from the frame
        binary_data = ''.join(str(value & 1) for value in flat_frame)
        delimiter = '1111111111111110'

        if delimiter not in binary_data:
            shutil.rmtree(temp_dir)
            return render(request, 'video_decryption.html', {
                'message': '❌ No hidden text found in the video.'
            })

        # Get binary message before delimiter
        split_data = binary_data.split(delimiter)[0]
        split_data = split_data[:len(split_data) - (len(split_data) % 8)]

        # Convert binary to text
        decoded_text = ''.join(
            chr(int(split_data[i:i + 8], 2)) for i in range(0, len(split_data), 8)
        )

        shutil.rmtree(temp_dir)

        return render(request, 'video_decryption.html', {
            'extracted_text': decoded_text,
            'message': '✅ Hidden text extracted successfully.'
        })

    return render(request, 'video_decryption.html')


# ========================== MORPH CODE STEGANOGRAPHY ==========================

MORSE_CODE_DICT = {
    'A': '.-',    'B': '-...',  'C': '-.-.',  'D': '-..',   'E': '.',
    'F': '..-.',  'G': '--.',   'H': '....',  'I': '..',    'J': '.---',
    'K': '-.-',   'L': '.-..',  'M': '--',    'N': '-.',    'O': '---',
    'P': '.--.',  'Q': '--.-',  'R': '.-.',   'S': '...',   'T': '-',
    'U': '..-',   'V': '...-',  'W': '.--',   'X': '-..-',  'Y': '-.--',
    'Z': '--..',
    '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
    '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
    ' ': '/',     ',': '--..--', '.': '.-.-.-', '?': '..--..', '!': '-.-.--',
    ':': '---...', ';': '-.-.-.', "'": '.----.', '"': '.-..-.', '-': '-....-',
    '/': '-..-.',  '(': '-.--.',  ')': '-.--.-', '&': '.-...',
    '=': '-...-',  '+': '.-.-.',  '_': '..--.-', '$': '...-..-', '@': '.--.-.',
}

REVERSE_MORSE_DICT = {v: k for k, v in MORSE_CODE_DICT.items()}


def morph_code_selection(request):
    return render(request, 'morph_code_selection.html')


def morph_encode(request):
    encoded_text = ""
    if request.method == "POST":
        original_text = request.POST.get("text", "")
        encoding_type = request.POST.get("encoding_type", "")

        if original_text:
            if encoding_type == "binary":
                encoded_text = ' '.join(format(ord(char), '08b') for char in original_text)
            elif encoding_type == "hex":
                encoded_text = original_text.encode().hex()
            elif encoding_type == "reverse":
                encoded_text = original_text[::-1]
            elif encoding_type == "base64":
                encoded_text = base64.b64encode(original_text.encode()).decode()
            elif encoding_type == "dotdash":
                encoded_text = ' '.join(MORSE_CODE_DICT.get(char.upper(), '?') for char in original_text)
            else:
                encoded_text = "❌ Invalid encoding type selected."

    return render(request, "morph_encode.html", {"encoded_text": encoded_text})


def morph_decode(request):
    decoded_text = ""
    if request.method == "POST":
        morphed_text = request.POST.get("morphed_text", "").strip()

        try:
            if all(c in "01 " for c in morphed_text):
                # Binary decode
                decoded_text = ''.join(chr(int(b, 2)) for b in morphed_text.split() if len(b) == 8)
            elif all(c in "0123456789abcdefABCDEF" for c in morphed_text.replace(" ", "")):
                # Hex decode
                decoded_text = bytes.fromhex(morphed_text.replace(" ", "")).decode()
            elif set(morphed_text).issubset({'.', '-', ' ', '/'}):
                # Dot & Dash (Morse) decode
                decoded_text = ''.join(REVERSE_MORSE_DICT.get(code, '?') for code in morphed_text.split())
            else:
                try:
                    # Base64 decode
                    decoded_text = base64.b64decode(morphed_text).decode()
                except (binascii.Error, UnicodeDecodeError):
                    # Fallback to reverse
                    decoded_text = morphed_text[::-1]
        except Exception:
            decoded_text = "❌ Unable to decode the text."

    return render(request, "morph_decode.html", {"decoded_text": decoded_text})