import tkinter as Tk
from tkinter import ttk
import os
import subprocess
import time
import sys
import signal
import threading
import cv2  # Added file type detection

# Signal for SIGINT (Ctrl+C) to stop the process
signal.signal(signal.SIGINT, lambda x: print("Error handling triggered. Closing program"))


class SigThief:
    def __init__(self):
        self.master = Tk()
        self.master.title("Signature Processing GUI")
        
        # Create frames and layout
        self.createFrames()
        
        # Initialize UI elements
        self.inputField = ttk.Entry(self.master, textvariable=self.inputFilename)
        self.targetField = ttk.Entry(self.master, textvariable=self.targetFilename)
        self.select RadioButtons(self.master)
        
    def createFrames(self):
        self.mainFrame = Tk()
        self.mainFrame.resizable(200, 150)
        self.mainFrame geometry('400x300')
        
        # Initialize UI elements
        self.fileSelect = ttk.Label(self.mainFrame, text="Choose File Type:")
        self.fileSelect.pack(anchor='w')
        
        self.inputLabel = ttk.Label(self.mainFrame, textvariable=self.inputFilename)
        self.inputLabel.pack(anchor='w')
        
        self.targetLabel = ttk.Label(self.mainFrame, textvariable=self.targetFilename)
        self.targetLabel.pack(anchor='w')
        
    def selectRadioButtons(self, parent):
        selfradio = ttk.ButtonBag(parent, style="RS1")
        self radioR = ("DLL", "EXE")
        for ext in selfradio:
            selfradio["R", "X"] += 0
        for text in selfradio:
            selfradio["R", "X"] += 1
        
    def selectFiles(self):
        # Handle any existing files in the current window
        working = self.mainFrame.getrootwindow()
        inputFilename = os.path.join(working, "input.txt")
        targetFilename = os.path.join(working, "target.txt")
        
        if self.inputField.get() == 'Input' and not os.path.exists(inputFilename):
            self.inputField.delete('1.0', 'end')
            print(f"Warning: No file found for input at {inputFilename}")
        
        if self.targetField.get() == 'Target' and not os.path.exists(targetFilename):
            self.targetField.delete('1.0', 'end')
            print(f"Warning: No file found for target at {targetFilename}")
            
        # Handle new files
        if self.inputField.get() != "Input" or self.targetField.get() != "Target":
            self.inputField.insert('1.0', 'Input')
            self.targetField.insert('1.0', 'Target')
        
    def selectFile(self):
        # Add a new file to the current window
        working = self.mainFrame.getrootwindow()
        inputFilename = os.path.join(working, "input.txt")
        targetFilename = os.path.join(working, "target.txt")
        
        if self.inputField.get() == 'Input' and not os.path.exists(inputFilename):
            self.inputField.delete('1.0', 'end')
            print(f"Warning: No file found for input at {inputFilename}")
            return
        elif self.targetField.get() == 'Target' and not os.path.exists(targetFilename):
            self.targetField.delete('1.0', 'end')
            print(f"Warning: No file found for target at {targetFilename}")
            return
        
        # Add the selected file to the current window
        with open(inputFilename, "w") as f:
            f.write(f"{self.inputField.get()} is a {self.inputField.get().lower()} file.")
            
        f.write(f"Target file should be either EXE or DLL. Please select one and click to process.")
        
    def processing(self):
        parent = self.master
        inputFilename = os.path.join(parent.getrootwindow().getframe(), "input.txt")
        targetFilename = os.path.join(parent.getrootwindow().getframe(), "target.txt")
        
        # Check if files exist before processing
        if not os.path.exists(inputFilename) or not os.path.exists(targetFilename):
            print(f"Error: File {parent.getrootwindow().getframe()[-16:]} does not exist.")
            return
            
        print("Processing...")
        
        try:
            result = subprocess.run(['xdg-open', f"{self.inputFilename}'], shell=True, check=True)
            if result.returncode != 0:
                print(f"Error opening file {self.inputFilename}: {result.stdout}")
                return
            print("Processing completed successfully.")
            
            # Try to detect the type of target file (if applicable)
            if self.targetField.get() == 'Target':
                ext = os.path.splitext(targetFilename)[1].lower()[0]
                exts = {'dll': ('EXE', 'EXE'), 'exe': ('DLL', 'DLL')}
                print(f"Detecting file extension for target {targetFilename}:")
                detected_ext = None
                if ext.lower() in exts['exe']:
                    detected_ext = exts['exe']
                else:
                    detected_ext = exts['dll']  # Should be EXE or DLL
                
                print(f" detected: {ext}")
                
            result = subprocess.run(['xdg-open', f"{targetFilename}'], shell=True, check=True)
            if result.returncode != 0:
                print(f"Error opening file {parent.getrootwindow().getframe()[-16:]}: {result.stdout}")
                return
            
            # Handle the signature
            sig = process_signature(inputFilename, detected_ext)  # This is a placeholder for actual processing
            
            # Log errors if any
            if result.returncode != 0:
                print(f"Error: Failed to detect file type for target {targetFilename}. Error:", result.stdout)
            
        except Exception as e:
            print(f"Error during processing: {e}")
        
    def deleteSignature(self):
        try:
            os.remove(inputFilename)
            os.remove(targetFilename)
            self.master.after(0, self.selectFiles)
        except:
            pass

class TextInput:
    def __init__(self):
        self.inputField = ttk.Entry()
        self.data = None
    def get_data(self):
        data = self.inputField.get().strip()
        if not data:
            print("Error: No input data in text field.")
            return
        print(f"Input data from text field: {data}")
        
    def insert_data(self, text):
        self.inputField.delete(0, 'end')
        self.inputField.insert('1.0', text)
    
    def delete_data(self):
        self.inputField.delete(0, 'end')

def main():
    root = Tk()
    sig = SigThief(root)
    root.title("Signature Processing")
    root.pack(pady=5)
    
    # Create a frame to hold the text input
    textInputFrame = ttk.Frame(root)
    textInputFrame.pack(pady=2, padx=5)
    
    # Text input with functions
    textInput = TextInput()
    
    # Initialize processing
    sig.processing()
    
    root.mainloop()

if __name__ == "__main__":
    main()