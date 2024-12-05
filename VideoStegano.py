import cv2
import os
import numpy as np
import tkinter as tk
from tkinter import filedialog

# Function to convert message to binary
def msgtobinary(msg):
    if isinstance(msg, str):
        result = ''.join([format(ord(i), "08b") for i in msg])
    elif isinstance(msg, (bytes, np.ndarray)):
        result = [format(i, "08b") for i in msg]
    elif isinstance(msg, (int, np.uint8)):
        result = format(msg, "08b")
    else:
        raise TypeError("Input type is not supported in this function")
    return result

# RC4 Key Scheduling Algorithm (KSA)
def KSA(key):
    key_length = len(key)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]
    return S

# RC4 Pseudo-Random Generation Algorithm (PRGA)
def PRGA(S, n):
    i = 0
    j = 0
    key = []
    while n > 0:
        n -= 1
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        key.append(K)
    return key

# Prepare the key array
def preparing_key_array(s):
    return [ord(c) for c in s]

# Encryption using RC4
def encryption(plaintext, key):
    key = preparing_key_array(key)
    S = KSA(key)
    keystream = np.array(PRGA(S, len(plaintext)))
    plaintext = np.array([ord(i) for i in plaintext])
    cipher = keystream ^ plaintext
    return ''.join(chr(c) for c in cipher)

# Decryption using RC4
def decryption(ciphertext, key):
    key = preparing_key_array(key)
    S = KSA(key)
    keystream = np.array(PRGA(S, len(ciphertext)))
    ciphertext = np.array([ord(i) for i in ciphertext])
    decoded = keystream ^ ciphertext
    return ''.join(chr(c) for c in decoded)

# Embedding the encrypted message into the video frame
def embed(frame, data, key):
    data = encryption(data, key)
    if not data:
        raise ValueError('Data entered to be encoded is empty')
    data += '*^*^*'
    binary_data = msgtobinary(data)
    index_data = 0
    for i in range(frame.shape[0]):
        for j in range(frame.shape[1]):
            r, g, b = frame[i, j]
            if index_data < len(binary_data):
                frame[i, j, 0] = int(msgtobinary(r)[:-1] + binary_data[index_data], 2)
                index_data += 1
            if index_data < len(binary_data):
                frame[i, j, 1] = int(msgtobinary(g)[:-1] + binary_data[index_data], 2)
                index_data += 1
            if index_data < len(binary_data):
                frame[i, j, 2] = int(msgtobinary(b)[:-1] + binary_data[index_data], 2)
                index_data += 1
            if index_data >= len(binary_data):
                break
        if index_data >= len(binary_data):
            break
    return frame

# Extracting the encrypted message from the video frame
def extract(frame, key):
    data_binary = ""
    for i in range(frame.shape[0]):
        for j in range(frame.shape[1]):
            r, g, b = frame[i, j]
            r = msgtobinary(r)
            g = msgtobinary(g)
            b = msgtobinary(b)
            data_binary += r[-1]
            data_binary += g[-1]
            data_binary += b[-1]
            total_bytes = [data_binary[i: i + 8] for i in range(0, len(data_binary), 8)]
            decoded_data = ""
            for byte in total_bytes:
                decoded_data += chr(int(byte, 2))
                if decoded_data[-5:] == "*^*^*":
                    decoded_data = decoded_data[:-5]
                    final_decoded_msg = decryption(decoded_data, key)
                    print("\n\nThe Encoded data which was hidden in the Video was :-- ", final_decoded_msg)
                    return
    print("\nNo hidden message found.")

# Decoding the video data
def decode_vid_data(key):
    root = tk.Tk()
    root.withdraw()
    print("\tSelect the video")
    root.attributes('-alpha', 0.0)
    root.attributes('-topmost', True)
    video_path = filedialog.askopenfilename(title="Select a video to decode the message")

    if video_path:
        cap = cv2.VideoCapture(video_path)
        max_frame = 0
        while cap.isOpened():
            ret, _ = cap.read()
            if not ret:
                break
            max_frame += 1
        cap.release()
        print("Total number of Frames in selected Video:", max_frame)
        print("Enter the secret frame number from where you want to extract data: ", end='')
        n = int(input())
        vidcap = cv2.VideoCapture(video_path)
        frame_number = 0
        while vidcap.isOpened():
            ret, frame = vidcap.read()
            if not ret:
                break
            frame_number += 1
            if frame_number == n:
                extract(frame, key)
                return

# Encoding the video data
def encode_vid_data():
    root = tk.Tk()
    root.withdraw()
    root.attributes('-alpha', 0.0)
    root.attributes('-topmost', True)
    video_path = filedialog.askopenfilename(title="Select a video to embed message")

    if video_path:
        cap = cv2.VideoCapture(video_path)
        vidcap = cv2.VideoCapture(video_path)
        fourcc = cv2.VideoWriter_fourcc(*'mp4v')
        frame_width = int(vidcap.get(3))
        frame_height = int(vidcap.get(4))
        size = (frame_width, frame_height)
        filename = os.path.splitext(os.path.basename(video_path))[0]
        output_filename = os.path.join('./Result_files', f'{filename}_embedded.mp4')
        out = cv2.VideoWriter(output_filename, fourcc, 25.0, size)

        max_frame = 0
        print("\n\t Reading video frames, Wait ...\n")
        while cap.isOpened():
            ret, _ = cap.read()
            if not ret:
                break
            max_frame += 1
        cap.release()
        print("Total number of Frames in selected Video: ", max_frame)
        print("Enter the frame number where you want to embed data: ", end='')
        n = int(input())
        frame_number = 0
        while vidcap.isOpened():
            ret, frame = vidcap.read()
            if not ret:
                break
            frame_number += 1
            if frame_number == n:
                data = input("Enter the data to be embedded in the video: ")
                key = input("Enter the encryption key: ")
                frame = embed(frame, data, key)
            out.write(frame)

        print("\nEncoded the data successfully in the video file.")
        print("Encoded video saved at:", output_filename)
        return
    else:
        print("\n\tFile opening cancelled by user\n")

# Main function to handle user interaction
def vid_steg():
    print("Hidden Layers")
    while True:
        print("\nSELECT THE VIDEO STEGANOGRAPHY OPERATION\n")
        print("1. Encode the Text message")
        print("2. Decode the Text message")
        print("3. Exit")
        choice1 = int(input("Enter the Choice: "))
        if choice1 == 1:
            print("\tSelect the video file")
            encode_vid_data()
        elif choice1 == 2:
            key = input("\tTell me that secret key: ")
            decode_vid_data(key)
        elif choice1 == 3:
            break
        else:
            print("Incorrect Choice")
        print("\n")

if __name__ == "__main__":
    vid_steg()
