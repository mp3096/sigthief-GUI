import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
import os
import struct
import shutil
import io
#t
def gather_file_info_win(binary):
    flItms = {}
    binary = open(binary, 'rb')
    binary.seek(int('3C', 16))
    flItms['buffer'] = 0
    flItms['JMPtoCodeAddress'] = 0
    flItms['dis_frm_pehdrs_sectble'] = 248
    flItms['pe_header_location'] = struct.unpack('<i', binary.read(4))[0]
    # Start of COFF
    flItms['COFF_Start'] = flItms['pe_header_location'] + 4
    binary.seek(flItms['COFF_Start'])
    flItms['MachineType'] = struct.unpack('<H', binary.read(2))[0]
    binary.seek(flItms['COFF_Start'] + 2, 0)
    flItms['NumberOfSections'] = struct.unpack('<H', binary.read(2))[0]
    flItms['TimeDateStamp'] = struct.unpack('<I', binary.read(4))[0]
    binary.seek(flItms['COFF_Start'] + 16, 0)
    flItms['SizeOfOptionalHeader'] = struct.unpack('<H', binary.read(2))[0]
    flItms['Characteristics'] = struct.unpack('<H', binary.read(2))[0]
    # End of COFF
    flItms['OptionalHeader_start'] = flItms['COFF_Start'] + 20

    #if flItms['SizeOfOptionalHeader']:
        #Begin Standard Fields section of Optional Header
    binary.seek(flItms['OptionalHeader_start'])
    flItms['Magic'] = struct.unpack('<H', binary.read(2))[0]
    flItms['MajorLinkerVersion'] = struct.unpack("!B", binary.read(1))[0]
    flItms['MinorLinkerVersion'] = struct.unpack("!B", binary.read(1))[0]
    flItms['SizeOfCode'] = struct.unpack("<I", binary.read(4))[0]
    flItms['SizeOfInitializedData'] = struct.unpack("<I", binary.read(4))[0]
    flItms['SizeOfUninitializedData'] = struct.unpack("<I",
                                                           binary.read(4))[0]
    flItms['AddressOfEntryPoint'] = struct.unpack('<I', binary.read(4))[0]
    flItms['PatchLocation'] = flItms['AddressOfEntryPoint']
    flItms['BaseOfCode'] = struct.unpack('<I', binary.read(4))[0]
    if flItms['Magic'] != 0x20B:
        flItms['BaseOfData'] = struct.unpack('<I', binary.read(4))[0]
    # End Standard Fields section of Optional Header
    # Begin Windows-Specific Fields of Optional Header
    if flItms['Magic'] == 0x20B:
        flItms['ImageBase'] = struct.unpack('<Q', binary.read(8))[0]
    else:
        flItms['ImageBase'] = struct.unpack('<I', binary.read(4))[0]
    flItms['SectionAlignment'] = struct.unpack('<I', binary.read(4))[0]
    flItms['FileAlignment'] = struct.unpack('<I', binary.read(4))[0]
    flItms['MajorOperatingSystemVersion'] = struct.unpack('<H',
                                                               binary.read(2))[0]
    flItms['MinorOperatingSystemVersion'] = struct.unpack('<H',
                                                               binary.read(2))[0]
    flItms['MajorImageVersion'] = struct.unpack('<H', binary.read(2))[0]
    flItms['MinorImageVersion'] = struct.unpack('<H', binary.read(2))[0]
    flItms['MajorSubsystemVersion'] = struct.unpack('<H', binary.read(2))[0]
    flItms['MinorSubsystemVersion'] = struct.unpack('<H', binary.read(2))[0]
    flItms['Win32VersionValue'] = struct.unpack('<I', binary.read(4))[0]
    flItms['SizeOfImageLoc'] = binary.tell()
    flItms['SizeOfImage'] = struct.unpack('<I', binary.read(4))[0]
    flItms['SizeOfHeaders'] = struct.unpack('<I', binary.read(4))[0]
    flItms['CheckSum'] = struct.unpack('<I', binary.read(4))[0]
    flItms['Subsystem'] = struct.unpack('<H', binary.read(2))[0]
    flItms['DllCharacteristics'] = struct.unpack('<H', binary.read(2))[0]
    if flItms['Magic'] == 0x20B:
        flItms['SizeOfStackReserve'] = struct.unpack('<Q', binary.read(8))[0]
        flItms['SizeOfStackCommit'] = struct.unpack('<Q', binary.read(8))[0]
        flItms['SizeOfHeapReserve'] = struct.unpack('<Q', binary.read(8))[0]
        flItms['SizeOfHeapCommit'] = struct.unpack('<Q', binary.read(8))[0]

    else:
        flItms['SizeOfStackReserve'] = struct.unpack('<I', binary.read(4))[0]
        flItms['SizeOfStackCommit'] = struct.unpack('<I', binary.read(4))[0]
        flItms['SizeOfHeapReserve'] = struct.unpack('<I', binary.read(4))[0]
        flItms['SizeOfHeapCommit'] = struct.unpack('<I', binary.read(4))[0]
    flItms['LoaderFlags'] = struct.unpack('<I', binary.read(4))[0]  # zero
    flItms['NumberofRvaAndSizes'] = struct.unpack('<I', binary.read(4))[0]
    # End Windows-Specific Fields of Optional Header
    # Begin Data Directories of Optional Header
    flItms['ExportTableRVA'] = struct.unpack('<I', binary.read(4))[0]
    flItms['ExportTableSize'] = struct.unpack('<I', binary.read(4))[0]
    flItms['ImportTableLOCInPEOptHdrs'] = binary.tell()
    #ImportTable SIZE|LOC
    flItms['ImportTableRVA'] = struct.unpack('<I', binary.read(4))[0]
    flItms['ImportTableSize'] = struct.unpack('<I', binary.read(4))[0]
    flItms['ResourceTable'] = struct.unpack('<Q', binary.read(8))[0]
    flItms['ExceptionTable'] = struct.unpack('<Q', binary.read(8))[0]
    flItms['CertTableLOC'] = binary.tell()
    flItms['CertLOC'] = struct.unpack("<I", binary.read(4))[0]
    flItms['CertSize'] = struct.unpack("<I", binary.read(4))[0]
    binary.close()
    return flItms

def copy_cert(exe):
    flItms = gather_file_info_win(exe)
    if flItms['CertLOC'] == 0 or flItms['CertSize'] == 0:
        raise ValueError("Input file is not signed!")
    with open(exe, 'rb') as f:
        f.seek(flItms['CertLOC'], 0)
        cert = f.read(flItms['CertSize'])
    return cert

def write_cert(cert, exe, output):
    flItms = gather_file_info_win(exe)
    if not output: 
        output = str(exe) + "_signed"
    shutil.copy2(exe, output)
    with open(exe, 'rb') as g:
        with open(output, 'wb') as f:
            f.write(g.read())
            f.seek(0)
            f.seek(flItms['CertTableLOC'], 0)
            f.write(struct.pack("<I", len(open(exe, 'rb').read())))
            f.write(struct.pack("<I", len(cert)))
            f.seek(0, io.SEEK_END)
            f.write(cert)

def truncate(exe, output):
    flItms = gather_file_info_win(exe)
    if flItms['CertLOC'] == 0 or flItms['CertSize'] == 0:
        raise ValueError("Input file is not signed!")
    if not output:
        output = str(exe) + "_nosig"
    shutil.copy2(exe, output)
    with open(output, "r+b") as binary:
        binary.seek(-flItms['CertSize'], io.SEEK_END)
        binary.truncate()
        binary.seek(flItms['CertTableLOC'], 0)
        binary.write(b"\x00\x00\x00\x00\x00\x00\x00\x00")

def add_signature(input_file, target_file, output_file):
    try:
        cert = copy_cert(input_file)
        write_cert(cert, target_file, output_file)
        messagebox.showinfo("Success", "Signature appended. Output file: {}".format(output_file))
    except Exception as e:
        messagebox.showerror("Error", str(e))

def output_cert(exe, output):
    cert = copy_cert(exe)
    if not output:
        output = str(exe) + "_sig"
    open(output, 'wb').write(cert)
    messagebox.showinfo("Success", "Signature ripped. Output file: {}".format(output))

def check_signature(exe):
    flItms = gather_file_info_win(exe)
    if flItms['CertLOC'] == 0 or flItms['CertSize'] == 0:
        messagebox.showinfo("Information", "Input file is not signed!")
    else:
        messagebox.showinfo("Information", "Input file is signed!")

class SigThiefGUI:
    def __init__(self, master):
        self.master = master
        master.title("Signature Thief")

        # Input File
        self.input_label = tk.Label(master, text="Input File:")
        self.input_label.grid(row=0, column=0, sticky=tk.W)

        self.input_entry = tk.Entry(master, width=50)
        self.input_entry.grid(row=0, column=1)

        self.browse_input_button = tk.Button(master, text="Browse", command=self.browse_input)
        self.browse_input_button.grid(row=0, column=2)

        # Target File
        self.target_label = tk.Label(master, text="Target File:")
        self.target_label.grid(row=1, column=0, sticky=tk.W)

        self.target_entry = tk.Entry(master, width=50)
        self.target_entry.grid(row=1, column=1)

        self.browse_target_button = tk.Button(master, text="Browse", command=self.browse_target)
        self.browse_target_button.grid(row=1, column=2)

        # Output File
        self.output_label = tk.Label(master, text="Output File:")
        self.output_label.grid(row=2, column=0, sticky=tk.W)

        self.output_entry = tk.Entry(master, width=50)
        self.output_entry.grid(row=2, column=1)

        self.browse_output_button = tk.Button(master, text="Browse", command=self.browse_output)
        self.browse_output_button.grid(row=2, column=2)

        # Buttons
        self.add_button = tk.Button(master, text="Add Signature", command=self.add_signature)
        self.add_button.grid(row=3, column=0)

        self.output_button = tk.Button(master, text="Output Signature", command=self.output_signature)
        self.output_button.grid(row=3, column=1)

        self.check_button = tk.Button(master, text="Check Signature", command=self.check_signature)
        self.check_button.grid(row=3, column=2)

        self.truncate_button = tk.Button(master, text="Truncate Signature", command=self.truncate_signature)
        self.truncate_button.grid(row=3, column=3)

    def browse_input(self):
        filename = filedialog.askopenfilename(initialdir=os.getcwd(), title="Select Input File")
        self.input_entry.delete(0, tk.END)
        self.input_entry.insert(0, filename)

    def browse_target(self):
        filename = filedialog.askopenfilename(initialdir=os.getcwd(), title="Select Target File")
        self.target_entry.delete(0, tk.END)
        self.target_entry.insert(0, filename)

    def browse_output(self):
        filename = filedialog.asksaveasfilename(initialdir=os.getcwd(), title="Select Output File", defaultextension=".exe")
        self.output_entry.delete(0, tk.END)
        self.output_entry.insert(0, filename)

    def add_signature(self):
        input_file = self.input_entry.get()
        target_file = self.target_entry.get()
        output_file = self.output_entry.get()
        if not input_file or not target_file or not output_file:
            messagebox.showerror("Error", "Please select input, target, and output files.")
            return
        add_signature(input_file, target_file, output_file)

    def output_signature(self):
        input_file = self.input_entry.get()
        output_file = self.output_entry.get()
        if not input_file or not output_file:
            messagebox.showerror("Error", "Please select input and output files.")
            return
        output_cert(input_file, output_file)

    def check_signature(self):
        input_file = self.input_entry.get()
        if not input_file:
            messagebox.showerror("Error", "Please select an input file.")
            return
        check_signature(input_file)

    def truncate_signature(self):
        input_file = self.input_entry.get()
        output_file = self.output_entry.get()
        if not input_file or not output_file:
            messagebox.showerror("Error", "Please select input and output files.")
            return
        try:
            truncate(input_file, output_file)
            messagebox.showinfo("Success", "Signature removed. Output file: {}".format(output_file))
        except Exception as e:
            messagebox.showerror("Error", str(e))

def main():
    root = tk.Tk()
    app = SigThiefGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
