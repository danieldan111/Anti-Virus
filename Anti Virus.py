import os

def folder_search(path, folder):
    for file in os.listdir(path):
        print(file + f"  --- {folder}")
        if (os.path.splitext(file)[1] == ""):
            folder_search(path + "/" + file, file)



first = "C:/Users/ADMIN/Desktop/Harel/BoazSharabis/Img"
folder_search(first, "main")