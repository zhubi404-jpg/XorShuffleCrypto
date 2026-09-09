#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
gui.py — 偏移加密工具图形界面 v2.0
依赖 core.py 加密引擎（支持协议版本1和2）
"""

import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import time
import base64
import secrets
import hashlib

# 导入核心引擎所有需要的符号
from core import (
    ENCODING_ID,
    RNG_ID,
    encrypt_with_offset,
    decrypt_with_offset,
    generate_offsets_manual,
    _BE,          # 仅供 generate_offset_popup 中哈希使用
)

# ================== GUI 主窗口 ===================
class OffsetEncryptApp:
    """主应用程序类 — 使用配置驱动 + 工厂模式构建 GUI"""

    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("偏移加密工具 v2.0")
        root.geometry("700x850")
        root.resizable(True, True)

        # ---------- 控件绑定变量 ----------
        self.rng_var = tk.StringVar(value="MersenneTwister")
        self.embed_var = tk.BooleanVar(value=True)   # 固定为 True，但允许用户尝试取消
        self.input_encoding_var = tk.StringVar(value="utf-8")
        self.base64_var = tk.BooleanVar(value=True)

        # ---------- 网格权重配置 ----------
        root.grid_rowconfigure(1, weight=1)
        root.grid_rowconfigure(9, weight=1)
        root.grid_columnconfigure(0, weight=1)
        root.grid_columnconfigure(1, weight=2)
        root.grid_columnconfigure(2, weight=1)

        # ---------- 构建 GUI ----------
        self._create_widgets()
        self.embed_var.trace_add('write', self._on_embed_toggle) #不告诉你

    # ==================== GUI 构建（工厂模式） ====================
    def _create_widgets(self):
        """使用按行分组的配置驱动 + 工厂模式构建 GUI"""
        row_configs = [
            # 行 0: 输入文本标签
            [{"type": "label", "text": "输入文本 (明文或密文)", "column": 0,
              "sticky": "w", "padx": 5, "pady": 5}],

            # 行 1: 输入文本框（占三列）
            [{"type": "scrolledtext", "name": "input_text", "column": 0,
              "columnspan": 3, "sticky": "nsew", "padx": 5, "pady": 5,
              "height": 5, "wrap": tk.WORD}],

            # 行 2: 偏移序列
            [
                {"type": "label", "text": "偏移序列（逗号分隔，留空自动随机）", "column": 0,
                 "sticky": "w", "padx": 5, "pady": 2},
                {"type": "entry", "name": "offset_entry", "column": 1,
                 "sticky": "ew", "padx": 5, "pady": 2},
                {"type": "button", "text": "生成偏移", "command": self.generate_offset_popup,
                 "column": 2, "sticky": "e", "padx": 5, "pady": 2},
            ],

            # 行 3: 随机算法选择
            [
                {"type": "label", "text": "随机模式算法:", "column": 0,
                 "sticky": "w", "padx": 5, "pady": 2},
                {"type": "combobox", "name": "rng_combo", "column": 1,
                 "sticky": "w", "padx": 5, "pady": 2,
                 "textvariable": self.rng_var, "values": list(RNG_ID.keys()), "width": 18},
                {"type": "label", "text": "（仅当偏移框为空时生效）", "column": 2,
                 "sticky": "w", "padx": 5, "fg": "gray"},
            ],

            # 行 4: 嵌入参数选项（可点击，彩蛋触发）
            [{"type": "checkbutton", "name": "embed_check", "column": 0,
              "columnspan": 3, "sticky": "w", "padx": 5, "pady": 5,
              "text": "将加密参数嵌入密文头部（自动解密）",
              "variable": self.embed_var}],

            # 行 5: 输入编码
            [
                {"type": "label", "text": "输入编码", "column": 0,
                 "sticky": "w", "padx": 5, "pady": 2},
                {"type": "combobox", "name": "input_encoding_combo", "column": 1,
                 "sticky": "w", "padx": 5, "pady": 2,
                 "textvariable": self.input_encoding_var, "values": list(ENCODING_ID.keys()),
                 "width": 15},
                {"type": "label", "text": "(加解密需一致)", "column": 2,
                 "sticky": "w", "padx": 5, "fg": "gray"},
            ],

            # 行 6: 密钥
            [
                {"type": "label", "text": "密钥字符串 (UTF-8)", "column": 0,
                 "sticky": "w", "padx": 5, "pady": 2},
                {"type": "entry", "name": "key_entry", "column": 1,
                 "sticky": "ew", "padx": 5, "pady": 2},
                {"type": "button", "text": "生成随机密钥", "command": self.generate_random_key,
                 "column": 2, "sticky": "w", "padx": 5, "pady": 2},
            ],

            # 行 7: Base64 输出
            [{"type": "checkbutton", "name": "base64_check", "column": 0,
              "columnspan": 3, "sticky": "w", "padx": 5, "pady": 5,
              "text": "Base64 输出 (推荐)", "variable": self.base64_var}],

            # 行 8: 结果标签
            [{"type": "label", "text": "结果", "column": 0,
              "sticky": "w", "padx": 5, "pady": 2}],

            # 行 9: 结果文本框
            [{"type": "scrolledtext", "name": "output_text", "column": 0,
              "columnspan": 3, "sticky": "nsew", "padx": 5, "pady": 5,
              "height": 5, "wrap": tk.WORD}],

            # 行 10: 状态栏
            [{"type": "status", "name": "status", "column": 0,
              "columnspan": 3, "sticky": "we", "padx": 5, "pady": 2,
              "text": "就绪", "fg": "green"}],
        ]

        root = self.root

        for row_idx, row_items in enumerate(row_configs):
            for item in row_items:
                item["row"] = row_idx
                widget = self._make_widget(item)
                if "name" in item:
                    setattr(self, item["name"], widget)
                grid_kw = {k: item[k] for k in ("row", "column", "sticky", "padx", "pady",
                                                "columnspan", "rowspan") if k in item}
                widget.grid(**grid_kw)

        # 按钮框架
        btn_frame = tk.Frame(root)
        btn_frame.grid(row=8, column=0, columnspan=3, pady=10, sticky="ew")
        tk.Button(btn_frame, text="加密", command=self.do_encrypt, width=10).pack(side="left", padx=5)
        tk.Button(btn_frame, text="解密", command=self.do_decrypt, width=10).pack(side="left", padx=5)
        tk.Button(btn_frame, text="清空", command=self.clear_all, width=10).pack(side="left", padx=5)

    def _make_widget(self, cfg: dict):
        typ = cfg["type"]
        kwargs = {}

        if typ == "label":
            kwargs["text"] = cfg.get("text", "")
            if "fg" in cfg:
                kwargs["fg"] = cfg["fg"]
            return tk.Label(self.root, **kwargs)

        elif typ == "entry":
            return tk.Entry(self.root, **kwargs)

        elif typ == "button":
            kwargs["text"] = cfg.get("text", "")
            if "command" in cfg:
                kwargs["command"] = cfg["command"]
            return tk.Button(self.root, **kwargs)

        elif typ == "checkbutton":
            kwargs["text"] = cfg.get("text", "")
            if "variable" in cfg:
                kwargs["variable"] = cfg["variable"]
            return tk.Checkbutton(self.root, **kwargs)

        elif typ == "combobox":
            if "textvariable" in cfg:
                kwargs["textvariable"] = cfg["textvariable"]
            if "values" in cfg:
                kwargs["values"] = cfg["values"]
            if "width" in cfg:
                kwargs["width"] = cfg["width"]
            return ttk.Combobox(self.root, **kwargs)

        elif typ == "scrolledtext":
            if "height" in cfg:
                kwargs["height"] = cfg["height"]
            if "wrap" in cfg:
                kwargs["wrap"] = cfg["wrap"]
            return scrolledtext.ScrolledText(self.root, **kwargs)

        elif typ == "status":
            kwargs["text"] = cfg.get("text", "")
            if "fg" in cfg:
                kwargs["fg"] = cfg["fg"]
            kwargs["anchor"] = "w"
            return tk.Label(self.root, **kwargs)

        else:
            raise ValueError(f"未知控件类型: {typ}")

    # ==================== 月计Project Moon ====================
    def _on_embed_toggle(self, *args):
        """当嵌入参数复选框被取消勾选时触发彩蛋弹窗"""
        if not self.embed_var.get():
            # 获取主窗口位置和尺寸
            root_x = self.root.winfo_x()
            root_y = self.root.winfo_y()
            root_width = self.root.winfo_width()
            root_height = self.root.winfo_height()

            # 创建窗口
            popup = tk.Toplevel(self.root)
            popup.title("你确定？")
            popup.resizable(False, False)
            popup.transient(self.root)
            popup.grab_set()

            tk.Label(popup, text="必须启用嵌入参数！\n请选择以下任意一个选项：",
                     font=("Arial", 12), pady=10).pack()

            btn_frame = tk.Frame(popup)
            btn_frame.pack(pady=10)

            def on_choice():
                self.embed_var.set(True)
                popup.destroy()

            for label in ["A. 启用嵌入参数", "B. 启用嵌入参数", "C. 启用嵌入参数"]:
                btn = tk.Button(btn_frame, text=label, command=on_choice, width=18)
                btn.pack(side="left", padx=5)

            def on_close():
                self.embed_var.set(True)
                popup.destroy()
            popup.protocol("WM_DELETE_WINDOW", on_close)

            # 强制更新布局以获取窗口实际尺寸
            popup.update_idletasks()
            # 获取窗口的实际尺寸
            popup_width = popup.winfo_reqwidth()
            popup_height = popup.winfo_reqheight()
            # 计算居中位置
            x = root_x + (root_width - popup_width) // 2
            y = root_y + (root_height - popup_height) // 2
            # 设置窗口位置（不改变尺寸）
            popup.geometry(f"+{x}+{y}")

    # ==================== 核心功能方法 ====================
    def generate_random_key(self):
        key = secrets.token_urlsafe(32)
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key)
        self.status.config(text="已生成随机密钥，请妥善保存", fg="blue")

    def do_encrypt(self):
        self.status.config(text="处理中...", fg="orange")
        self.root.update()
        try:
            plain = self.input_text.get("1.0", tk.END).rstrip('\n')
            if not plain:
                messagebox.showwarning("提示", "请输入明文")
                self.status.config(text="就绪", fg="green")
                return
            key_str = self.key_entry.get().strip()
            if not key_str:
                messagebox.showwarning("提示", "请设置密钥（建议使用生成的随机密钥）")
                self.status.config(text="就绪", fg="green")
                return
            input_enc = self.input_encoding_var.get().strip()
            # 强制启用嵌入参数
            embed = True
            offset_str = self.offset_entry.get().strip()
            rng_id = RNG_ID.get(self.rng_var.get(), 0)

            packet = encrypt_with_offset(plain, offset_str, key_str, input_enc,
                                         embed_params=embed, rng_id=rng_id,
                                         error_log=None)

            if self.base64_var.get():
                output = base64.b64encode(packet).decode('ascii')
            else:
                output = packet.hex()
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", output)
            self.status.config(text="加密成功", fg="green")
        except Exception as e:
            err_msg = f"加密失败: {str(e)}"
            messagebox.showerror("错误", err_msg)
            self.status.config(text="加密失败", fg="red")

    def do_decrypt(self):
        self.status.config(text="处理中...", fg="orange")
        self.root.update()
        try:
            b64 = self.input_text.get("1.0", tk.END).strip()
            if not b64:
                messagebox.showwarning("提示", "请输入密文")
                self.status.config(text="就绪", fg="green")
                return
            key_str = self.key_entry.get().strip()
            if not key_str:
                messagebox.showwarning("提示", "请输入密钥")
                self.status.config(text="就绪", fg="green")
                return
            input_enc = self.input_encoding_var.get().strip()
            # 强制启用嵌入参数
            embed = True
            offset_str = self.offset_entry.get().strip()

            try:
                packet = base64.b64decode(b64.encode('ascii'))
            except Exception as e:
                raise ValueError(f"Base64 解码失败: {e}")

            plain = decrypt_with_offset(packet, offset_str, key_str, input_enc,
                                        embed_params=embed, error_log=None)

            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", plain)
            self.status.config(text="解密成功", fg="green")
        except Exception as e:
            err_msg = f"解密失败: {str(e)}"
            messagebox.showerror("错误", err_msg)
            self.status.config(text="解密失败", fg="red")

    def clear_all(self):
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)
        self.status.config(text="已清空", fg="blue")

    # ==================== 生成偏移弹出窗口 ====================
    def generate_offset_popup(self):
        plain = self.input_text.get("1.0", tk.END).rstrip('\n')
        if not plain:
            messagebox.showwarning("提示", "请先输入明文")
            return
        input_enc = self.input_encoding_var.get().strip()
        try:
            plain_bytes = plain.encode(input_enc)
            data_len = len(plain_bytes) + 4
            if data_len % 2 == 1:
                data_len += 1
            num_groups = data_len // 2
        except Exception as e:
            messagebox.showerror("错误", f"编码错误: {e}")
            return
        if num_groups <= 0:
            messagebox.showwarning("提示", "组数为0")
            return

        popup = tk.Toplevel(self.root)
        popup.title("生成偏移序列")
        popup.geometry("400x450")
        popup.resizable(True, True)

        tk.Label(popup, text=f"当前明文编码后组数: {num_groups}").pack(pady=5)
        tk.Label(popup, text="注意：生成后若修改明文，请重新生成！", fg="red").pack(pady=2)

        tk.Label(popup, text="随机算法:").pack()
        method_var = tk.StringVar(value=self.rng_var.get())
        method_menu = ttk.Combobox(popup, textvariable=method_var,
                                   values=list(RNG_ID.keys()), width=25)
        method_menu.pack(pady=5)

        tk.Label(popup, text="种子（可选）:").pack()
        seed_entry = tk.Entry(popup, width=30)
        seed_entry.pack(pady=5)

        tk.Label(popup, text="盐（字符串）:").pack()
        salt_entry = tk.Entry(popup, width=30)
        salt_entry.pack(pady=5)

        use_entropy_var = tk.BooleanVar(value=False)
        tk.Checkbutton(popup, text="混合系统熵", variable=use_entropy_var).pack(pady=5)

        preview_label = tk.Label(popup, text="", fg="blue", wraplength=380, justify='left')
        preview_label.pack(pady=5, fill=tk.X, expand=True)

        def on_generate():
            method = method_var.get()
            seed_str = seed_entry.get().strip()
            salt = salt_entry.get().strip()
            use_sys = use_entropy_var.get()
            seed = None
            if seed_str:
                try:
                    seed = int(seed_str)
                except ValueError:
                    seed = int.from_bytes(hashlib.sha256(seed_str.encode()).digest()[:8], _BE)
            try:
                offsets = generate_offsets_manual(method, num_groups, seed, salt, use_sys)
            except Exception as e:
                messagebox.showerror("错误", str(e))
                return
            offset_str = ','.join(map(str, offsets))
            self.offset_entry.delete(0, tk.END)
            self.offset_entry.insert(0, offset_str)
            preview = ', '.join(map(str, offsets[:20]))
            if len(offsets) > 20:
                preview += " ..."
            preview_label.config(text=f"预览: {preview}")
            popup.destroy()
            self.status.config(text=f"已生成 {method} 偏移序列，长度 {num_groups}", fg="blue")

        tk.Button(popup, text="生成并填入", command=on_generate, width=15).pack(pady=10)


# ================ 程序入口 ===================
def main():
    root = tk.Tk()
    app = OffsetEncryptApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()