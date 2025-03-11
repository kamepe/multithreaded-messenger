import tkinter as tk

root = tk.Tk()

root.title("Hello")
root.geometry("800x500")

label = tk.Label(root, text="HELLO",font=('Times new roman', 18))
label.pack()

root.mainloop()