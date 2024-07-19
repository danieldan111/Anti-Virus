import os
import requests
from hashlib import sha256
import tkinter as tk
from tkinter import *
from tkinter import filedialog




#tkinter setup
window = tk.Tk()
#getting screen width and height of display
width= window.winfo_screenwidth() 
height= window.winfo_screenheight()
#setting tkinter window size
window.geometry("%dx%d" % (width, height))
window.state('zoomed')

# window.geometry(f"{width}x{height}")
window.title("Anti Virus")

#window-props
icon = PhotoImage(file='Antilogo.png')
window.iconphoto(True, icon)
window.config(background="#161625")

#headline
label = Label(window, text="Daniel's Anti Virus", font=('Arial', 25),bg='#161625', fg='White')
label.pack()

def page_load():
    def keySet():
        global key
        key = key_entry.get()
        key_entry.config(state=DISABLED)
    def clearKey():
        global key
        key = ""
        key_entry.config(state=NORMAL)
        key_entry.delete(0,END)
    def browse_button():
        # Allow user to select a directory and store it in global var
        # called folder_path
        filename = filedialog.askdirectory()
        folder_path = filename


    frame1 = Frame(window, width=800, height=500,bg='#161625')
    frame1.pack(side=TOP, anchor=NW)
    frame1_1 = Frame(frame1, width=800, height=200, bg="#161625")
    frame1_1.pack()
    frame1_2 = Frame(frame1, width=800, height=200, bg="red")
    frame1_2.pack()
    frame1_3 = Frame(frame1, width=800, height=100, bg="white")
    frame1_3.pack()
    #frame1_1 components
    key_label = Label(frame1_1, text="API Key here", font=('Arial', 20),bg='#161625', fg='White')
    key_label.pack(side=TOP, anchor=NW)
    key_entry = Entry(frame1_1, font=("Arial", 23),width= 40)
    key_entry.pack(side=LEFT)
    key_margin = Label(frame1_1, text="", width=1, bg="#161625")
    key_margin.pack(side=LEFT)
    #set api
    key_btn = Button(frame1_1, text="Set Key", font=("Arial", 15), width= 7,height=1 ,command=keySet)
    key_btn.pack(side=LEFT)
    #clear api
    clear_key_btn = Button(frame1_1, text="Clear", font=("Arial", 15), width= 7,height=1 ,command=clearKey)
    clear_key_btn.pack(side=LEFT)
    #margin
    # browse_margin = Label(frame1, text="", width=100, bg="white")
    # browse_margin.pack()
    #path
    # button2 = Button(text="Browse", command=browse_button)
    # button2.pack()


page_load()

def scan():
    pass




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


    # first = "C:/Users/ADMIN/Pictures/Camera Roll"
    # number_of_files = count_files(first)
    global key
    print(key)

    # folder_search(first)
    # print("done scanning!")

    
window.mainloop()
