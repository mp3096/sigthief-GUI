# Signature Thief GUI

_For security professionals only..._

## What is this?

Over the years, testing against various Anti-Virus solutions has revealed that each product handles PE (Portable Executable) signatures differently. Some vendors prioritize certain certificate authorities without verifying the signature’s validity, while others simply check that the certificate table is populated. This disparity can lead to unexpected behavior during testing.

**Signature Thief GUI** is a tool designed for security researchers and penetration testers to help you quickly manipulate digital signatures within Windows executables and DLLs. With its intuitive graphical interface, you can easily:

- **Extract (Rip) a Signature:** Save a digital signature from a signed PE file to disk for later use.
- **Append a Signature:** Transfer a signature from one file and append it to another, updating the certificate table accordingly.
- **Check Signature Presence:** Determine whether a PE file is signed (note: this does not verify the signature’s cryptographic validity).
- **Truncate (Remove) a Signature:** Remove the signature from a PE file to analyze how certain Anti-Virus products handle unsigned binaries.

> **Note:** The signatures manipulated by this tool are not valid in terms of cryptographic verification—they’re intended solely for testing and research purposes.

## How It Works

The tool parses the PE header of a given executable (or DLL) using Python’s built-in `struct` module. It locates the certificate table entry and performs one of the following actions based on user input:
- **Extract the Certificate:** Read and save the digital signature.
- **Append the Certificate:** Inject a saved signature into a target file and update the certificate table.
- **Truncate the Certificate:** Remove the signature from a file.

The graphical user interface, built with Tkinter, provides a user-friendly method to select files and execute these operations without needing command-line interaction.

## Features

- **User-Friendly Interface:** A Tkinter-based GUI to browse and select files.
- **Signature Extraction:** Rip the digital signature from a signed PE file and save it to disk.
- **Signature Appending:** Append a ripped signature to another binary while updating the certificate table.
- **Signature Truncation:** Remove an existing signature from a binary.
- **Signature Check:** Quickly verify whether a file contains a digital signature.
- 
![Image](https://github.com/user-attachments/assets/d1ab9980-5aed-4cc2-b494-213f80574171)

## Getting Started
### Prerequisites

- Python 3.x
- Tkinter (usually included with standard Python distributions)
- Standard Python libraries: `os`, `struct`, `shutil`, `io`

### Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/mp3096/sigthief-GUI
   cd sigthief-GUI

2. Simply execute the main script:
   ```bash
   python main.py

This will launch the GUI.

Usage
Launch the GUI:
Run the application and the Signature Thief GUI window will appear.

Select Operation Mode:
Choose whether your target file is an EXE or DLL by selecting the appropriate radio button.

File Selection:
```bash
Input File: Browse and select the file from which the signature will be ripped or checked.
Target File: (Only for adding a signature) Browse and select the file to which the signature will be appended.
Output File: Specify where the resulting file should be saved.
Execute the Operation:

Add Signature: Extract the signature from the input file and append it to the target file.
Output Signature: Rip the signature and save it to disk.
Check Signature: Check if the input file is signed.
Truncate Signature: Remove the signature from the input file.
For example, to transfer a signature from a signed PE file to another binary:

Open the GUI.
Select the input (signed file), target, and output file.
Click the Add Signature button.
A success message will confirm the operation’s completion.
Disclaimer
This tool is intended solely for educational and research purposes. The creator is not responsible for any misuse or damage caused by this tool. Use it at your own risk, and always ensure you have proper authorization before testing any system or software.

Contributing
Feel free to fork the repository and submit pull requests if you have improvements or bug fixes. For major changes, please open an issue first to discuss what you would like to change.

License
This project is licensed under the MIT License. See the LICENSE file for details.

