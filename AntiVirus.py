import os
import requests

def folder_search(path):
    for file in os.listdir(path):
        print(file)
        try:
            if (os.path.splitext(file)[1] == ""):
                folder_search(path + "/" + file)
        except NotADirectoryError:
            pass
            



first = "C:/Users/ADMIN/Desktop/Harel/BoazSharabis/Img"
first = "C:/Users/ADMIN/Downloads"
folder_search(first)