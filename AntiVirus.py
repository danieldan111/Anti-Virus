import os
import requests
from hashlib import sha256

def hash_file(path):
    sha256_hash = sha256()
    with open(path,"rb") as f:
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def folder_search(path):
    for file in os.listdir(path):
        try:
            if (os.path.splitext(file)[1] == ""):
                folder_search(path + "/" + file)
            else:
                virusChecker(path + "/" + file)
        except NotADirectoryError:
            virusChecker(path + "/" + file)
            
def virusChecker(path):
    with open("VirusTotal-apikey.txt", 'r') as data:
        key = data.read()
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
    analysis = response.text[response.text.find("last_analysis_stats")::]
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
    
    
    


first = "C:/Users/ADMIN/Desktop/Harel/BoazSharabis/Img"
first = "C:/Users/ADMIN/Downloads"
with open("VirusTotal-apikey.txt", 'w') as api:
    key = input("enter your VirusTotal api key: ")
    api.write(key)

folder_search(first)
print("done scanning!")
