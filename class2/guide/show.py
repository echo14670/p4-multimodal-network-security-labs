import io,sys
p = r"C:\Users\lin20\Documents\ChatGPT\网络安全虚拟机安装\class2\guide\guide2_text.txt"
t = open(p, encoding="utf-8").read()
pages = t.split("===== PAGE ")
for pg in pages[4:8]:
    sys.stdout.write("===== PAGE " + pg + "\n")
