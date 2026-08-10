from tkinter import *
root = Tk()
root.attributes('-topmost', True)
root.geometry("400x300+300+120")
root.title("Pure Aura")
root.attributes('-alpha', 0.5)

frameCnt = 60
frames = [PhotoImage(file='pureaura.gif', format='gif -index %i' % (i)) for i in range(frameCnt)]

x = 300
y = 120
vx = 90
vy = 80
win_w = 400
win_h = 300

label = Label(root)
table = Label(root, text="This is Cyberpatriot Aura", font=("Helvetica", 16))
label.pack()
table.pack()


def update(ind):
    global x, y, vx, vy
    frame = frames[ind]
    ind += 1
    if ind == frameCnt:
        ind = 0
    label.configure(image=frame)

    x += vx
    y += vy
    screen_w = root.winfo_screenwidth()
    screen_h = root.winfo_screenheight()

    if x <= 0 or x + win_w >= screen_w:
        vx = -vx
        x += vx
    if y <= 0 or y + win_h >= screen_h:
        vy = -vy
        y += vy

    root.geometry(f"{win_w}x{win_h}+{x}+{y}")
    root.after(100, update, ind)

root.after(0, update, 0)
root.mainloop()