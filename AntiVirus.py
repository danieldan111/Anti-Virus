import os
import requests #pip install requests
from hashlib import sha256
import tkinter as tk
from tkinter import *
from tkinter import filedialog
from PIL import ImageTk, Image #pip install pillow
from tkinter import ttk



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
    def checkAPI():
        url = "https://www.virustotal.com/api/v3/files/59fce88da57e076536ccece2cd0b005991450b472d5de6de4f554d3ea1452ed5"

        headers = {
            "accept": "application/json",
            "x-apikey": f"{key}"
        }

        response = requests.get(url, headers=headers)
        message = response.text[response.text.find("message")::]
        message = message[0: message.find("\n")]
        if "Wrong API key" in message:
            clearKey()
            key_entry.insert(0,"Error: API key is not Valid")
            return 1
        return 0
    def checkPath():
        if (not os.path.isdir(path_entry.get())):
            clearPath()
            path_entry.insert(0,"Error: Invalid path")
            return 1
        path_entry.config(state=DISABLED)
        return 0

    def keySet():
        global key
        key = key_entry.get()
        key_entry.config(state=DISABLED)   
    def clearKey():
        global key
        key = ""
        key_entry.config(state=NORMAL)
        key_entry.delete(0,END)
    def clearPath():
        path_entry.config(state=NORMAL)
        path_entry.delete(0,END)
    def browse_button():
        # Allow user to select a directory and store it in global var
        # called folder_path
        path_entry.config(state=NORMAL)
        filename = filedialog.askdirectory()
        path_entry.delete(0,END)
        path_entry.insert(0, filename)

    def scan():
        keySet()
        Error_counter = 0
        #checking if the input is good:
        Error_counter += checkAPI()
        Error_counter += checkPath()
        
        if Error_counter == 0:
            begin_scan(path_entry.get())

    #i am dividing the window to 2 main frames, top and bottom        
    top_frame = Frame(window, width=width, height=450, bg="#161625")
    top_frame.pack()
    
    #marg from side
    marg_frames = Label(top_frame, text="",width=50, bg="#161625")
    marg_frames.pack(side=LEFT)
    #frame1
    frame1 = Frame(top_frame, width=900, height=450,bg='#161625')
    frame1.pack(side=LEFT, anchor=NW)
    frame1_1 = Frame(frame1, width=900, height=200, bg="#161625")
    frame1_1.pack(anchor=W)
    frame1_2 = Frame(frame1, width=900, height=200, bg="#161625")
    frame1_2.pack(anchor=W)
    frame1_3 = Frame(frame1, width=900, height=100, bg="#161625")
    frame1_3.pack(anchor=W)
    #frame1_1 components
    #marg
    marg_down = Label(frame1_1, text="",bg='#161625',height=5)
    marg_down.pack()
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
    #frame1_2
    #margin
    path_margin = Label(frame1_2, text="", height=1, bg="#161625")
    path_margin.pack()
    #path label
    path_label = Label(frame1_2, text="Path for scan", font=('Arial', 20),bg='#161625', fg='White')
    path_label.pack(side=TOP, anchor=NW)
    #path type
    path_entry = Entry(frame1_2, font=("Arial", 23),width= 40)
    path_entry.pack(side=LEFT)
    #btn margin
    path_btn_margin = Label(frame1_2, text="", width=1, bg="#161625")
    path_btn_margin.pack(side=LEFT)
    #path select
    path_select = Button(frame1_2,text="Browse", font=("Arial", 15),width= 7,height=1,command=browse_button)
    path_select.pack(side=LEFT)
    ##clear path
    clear_path_btn = Button(frame1_2, text="Clear", font=("Arial", 15), width= 7,height=1 ,command=clearPath)
    clear_path_btn.pack(side=LEFT)

    #frame2
    frame2 = Frame(top_frame, width=650, height=500,bg='red')
    frame2.pack(side=LEFT, anchor=NW)
    #image
    global big_image
    big_image = PhotoImage(file = "antiVirus-mainimg.png")
    canvas = Canvas(frame2,width = 400, height = 400, bg='#161625', highlightbackground = "#161625", highlightcolor= "#161625")
    canvas.create_image(200, 200, image = big_image)
    canvas.pack(side=RIGHT, anchor=N)
    #margin - top
    scan_marg_top = Label(frame1_3, text="", height=2, bg="#161625")
    scan_marg_top.pack()
    #margin - left
    scan_marg_left = Label(frame1_3, text="", width=59, bg="#161625")
    scan_marg_left.pack(side=LEFT)
    #scan btn
    scan_btn = Button(frame1_3, text="Scan", font=("Arial", 23) ,command=scan)
    scan_btn.pack()

    
    bottom_frame = Frame(window, width=width, height=500, bg = "#161625")
    bottom_frame.pack()
    
    global proggress_bar_label
    proggress_bar_label = Label(bottom_frame, text="Scan Proggress", font=("ariel", 40),bg = "#161625", fg='white')
    proggress_bar_label.pack_forget()

    global proggress_bar
    proggress_bar = ttk.Progressbar(bottom_frame, orient='horizontal',mode='determinate',length=500)
    proggress_bar.pack_forget()

    


page_load()


def begin_scan(path):
    
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
        if (resp.text.find("error")):
            analysis = resp.text[resp.text.find("error"): resp.text.find("message")]
            analysis = analysis[int(analysis.find("code")): int(analysis.find(","))]
            analysis = analysis[analysis.find(':') + 3 : -1]
            if (analysis == "QuotaExceededError"):
                raise Exception("QuotaExceededError")
        analysis = resp.text[resp.text.find("last_analysis_stats")::]
        analysis = analysis[0:analysis.find("}") + 1]
        for line in analysis.split("\n")[1:-1]:
            end_of_word = line.strip()[1::].find('"') + 1
            word_key = line.strip()[1: end_of_word]
            value = int(line.strip()[end_of_word + 3::].strip(","))
            if word_key == "malicious":
                if value > 0 :
                    print(f"this program may be malcius!, path: {path}")
                    viruses[path] = [value, 0]
            elif word_key == "suspicious":
                if value > 0 :
                    print(f"this program is sus!, path: {path}") 
                    try:
                        viruses[path][1] = value
                    except ValueError:
                        viruses[path] = [0,value]

    def virusChecker(path):
        global files_scanned
        files_scanned += 1
        try:
            hashed_file = hash_file(path)
        except PermissionError:
            return
        url = f"https://www.virustotal.com/api/v3/files/{hashed_file}" 
        global key
        headers = {
            "accept": "application/json",
            "x-apikey": f"{key}"
        }
        response = requests.get(url, headers=headers)
        try:
            analyze_response(response, path)
        except Exception("QuotaExceededError"):
            raise Exception("QuotaExceededError")

        proggress_bar["value"] = files_scanned / number_of_files * 100
        window.update()

    
    path_to_scan = f"{path}"
    number_of_files = count_files(path_to_scan)
    
    global viruses
    viruses = {}
    
    proggress_bar_label.pack()
    proggress_bar.pack()
    proggress_bar['value'] = 0
    
    try:
        folder_search(path_to_scan)
    except Exception("QuotaExceededError"):
        print("You run out of the 500 scan a day limit!")
    else:
        print("done scanning!")
    
    for item in viruses.items():
        fileName = item[0][::-1]
        fileName = fileName[0: fileName.find('/')][::-1]
        print(f"{fileName} has been flagged malicious by {item[1][0]} secuirty vendoes and suspicious by {item[1][1]}")


window.mainloop()
