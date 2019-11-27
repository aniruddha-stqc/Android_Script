from tkinter import filedialog
from tkinter import *

def browse_button():
    # Allow user to select a directory and store it in global var
    # called folder_path
    global folder_path
    root.directory = filedialog.askdirectory(initialdir="/root", title="Select Source Code Folder")
    filename = filedialog.askdirectory()
    folder_path.set(root.directory)
    print(filename)


root = Tk()
folder_path = StringVar()
lbl1 = Label(master=root,textvariable=folder_path)
lbl1.grid(row=0, column=1)
button2 = Button(text="Browse", command=browse_button)
button2.grid(row=0, column=3)

mainloop()