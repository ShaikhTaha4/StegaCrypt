import numpy as np
import scipy.io.wavfile as wav
import cv2
import os
import matplotlib.pyplot as plt
import librosa.display

# Convert image to spectrogram audio
def generate_audio_from_image(image_path):
    image = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
    
    # Normalize pixel values (0-1 range)
    image = image / 255.0
    
    # Convert image matrix to 1D waveform
    waveform = image.flatten()
    
    # Convert to audio signal
    sample_rate = 44100
    wavfile_path = 'static/hidden_audio.wav'
    wav.write(wavfile_path, sample_rate, waveform.astype(np.float32))
    
    return wavfile_path

# Convert spectrogram audio back to image
def extract_image_from_audio(audio_path):
    sample_rate, waveform = wav.read(audio_path)
    
    # Reshape waveform back to 2D image (assuming original dimensions known)
    image_size = (128, 128)  # Set the correct size
    image = np.reshape(waveform, image_size)
    
    # Convert back to 8-bit grayscale
    image = (image * 255).astype(np.uint8)
    
    # Save extracted image
    extracted_path = 'static/extracted_image.png'
    cv2.imwrite(extracted_path, image)
    
    return extracted_path
