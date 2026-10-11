import pdfplumber
src = r"C:\Users\lin20\Downloads\第2次实验材料_模态调度与异构封装\第2次实验材料_模态调度与异构封装\第二次实验指导_模态调度与异构封装.pdf"
out = r"C:\Users\lin20\Documents\ChatGPT\网络安全虚拟机安装\class2\guide\guide2_text.txt"
with pdfplumber.open(src) as pdf:
    parts = []
    for i, page in enumerate(pdf.pages, 1):
        parts.append("===== PAGE %d =====\n%s" % (i, page.extract_text() or ""))
    text = "\n\n".join(parts)
open(out, "w", encoding="utf-8").write(text)
print("PAGES", len(parts), "CHARS", len(text))
