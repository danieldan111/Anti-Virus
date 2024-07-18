import os
import requests
from hashlib import sha256
import tkinter as tk
from tkinter import *

def keySet():
    print(key_entry.get())
    key_entry.config(state=DISABLED)


#tkinter setup
window = tk.Tk()
width = 800
height = 800
window.geometry(f"{width}x{height}")
window.title("Anti Virus")
icon = PhotoImage(file='Antilogo.png')
window.iconphoto(True, icon)
window.config(background="#161625")
label = Label(window, text="Daniel's Anti Virus", font=('Arial', 25),bg='#161625', fg='White')
label.pack()


btn = Button(window, text="scan", font=("Arial", 15))
btn.place(x=500, y= 200) #button


key_label = Label(window, text="API Key here", font=('Arial', 20),bg='#161625', fg='White')
key_label.place(x = 20, y = 100)
key_entry = Entry(window, font=("Arial", 15),width=int(width * 0.6 / 10))
key_entry.place(x= 10, y = 150)
key_btn = Button(window, text="Set key", font=("Arial", 15), height=1 ,command=keySet)
key_btn.place(x = 550, y = 145)

def main():
    
    global files_scanned
    files_scanned = 0

    def hash_file(path):
        sha256_hash = sha256()
        with open(path,"rb") as f:
            for byte_block in iter(lambda: f.read(4096),b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    def count_files(path):
        files = 0
        for file in os.listdir(path):
            try:
                if (os.path.splitext(file)[1] == ""):
                    files += count_files(path + "/" + file)
                else:
                    files += 1
            except NotADirectoryError:
                files += 1
        return files
    def folder_search(path):
        for file in os.listdir(path):
            try:
                if (os.path.splitext(file)[1] == ""):
                    folder_search(path + "/" + file)
                else:
                    virusChecker(path + "/" + file)
            except NotADirectoryError:
                virusChecker(path + "/" + file)
    def analyze_response(resp, path):
        analysis = resp.text[resp.text.find("last_analysis_stats")::]
        analysis = analysis[0:analysis.find("}") + 1]
        for line in analysis.split("\n")[1:-1]:
            end_of_word = line.strip()[1::].find('"') + 1
            word_key = line.strip()[1: end_of_word]
            value = int(line.strip()[end_of_word + 3::].strip(","))
            if word_key == "malicious":
                if value > 0 :
                    print(f"this program may be malcius!, path: {path}")
            elif word_key == "suspicious":
                if value > 0 :
                    print(f"this program is sus!, path: {path}")     
    def virusChecker(path):
        global files_scanned
        files_scanned += 1
        try:
            hashed_file = hash_file(path)
        except PermissionError:
            return
        url = f"https://www.virustotal.com/api/v3/files/{hashed_file}" 
        headers = {
            "accept": "application/json",
            "x-apikey": f"{key}"
        }
        response = requests.get(url, headers=headers)
        analyze_response(response, path)
        print(f"{files_scanned / number_of_files * 100}% done!")


    first = "C:/Users/ADMIN/Pictures/Camera Roll"
    number_of_files = count_files(first)
    
    key = input("enter your VirusTotal api key: ")

    folder_search(first)
    print("done scanning!")

    
window.mainloop()