#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
gui.py — 偏移加密工具图形界面
依赖 core.py 加密引擎
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
        root.title("偏移加密工具 v1.0")
        root.geometry("700x850")
        root.resizable(True, True)

        # ---------- 控件绑定变量 ----------
        self.rng_var = tk.StringVar(value="MersenneTwister")
        self.embed_var = tk.BooleanVar(value=True)
        self.input_encoding_var = tk.StringVar(value="utf-8")
        self.base64_var = tk.BooleanVar(value=True)

        # ---------- 日志管理 ----------
        self.logs = []          # 仅存储错误日志
        self.max_logs = 50
        self.check_window = None
        self.tree = None
        self.view_mode = "group"

        # ---------- 网格权重配置 ----------
        root.grid_rowconfigure(1, weight=1)   # 输入文本框
        root.grid_rowconfigure(9, weight=1)   # 输出文本框
        root.grid_columnconfigure(0, weight=1)
        root.grid_columnconfigure(1, weight=2)
        root.grid_columnconfigure(2, weight=1)

        # ---------- 构建 GUI ----------
        self._create_widgets()

    # ==================== GUI 构建（工厂模式） ====================
    def _create_widgets(self):
        """使用按行分组的配置驱动 + 工厂模式构建 GUI"""
        row_configs = [
            # 行 0: 输入文本标签
            [{"type": "label", "text": "输入文本 (明文或密文)", "column": 0,
              "sticky": "w", "padx": 5, "pady": 5}],

            # 行 1: 输入文本框（占三列）—— 对应 weight=1
            [{"type": "scrolledtext", "name": "input_text", "column": 0,
              "columnspan": 3, "sticky": "nsew", "padx": 5, "pady": 5,
              "height": 5, "wrap": tk.WORD}],

            # 行 2: 偏移序列（三个控件同行）
            [
                {"type": "label", "text": "偏移序列（逗号分隔，留空自动随机）", "column": 0,
                 "sticky": "w", "padx": 5, "pady": 2},
                {"type": "entry", "name": "offset_entry", "column": 1,
                 "sticky": "ew", "padx": 5, "pady": 2},
                {"type": "button", "text": "生成偏移", "command": self.generate_offset_popup,
                 "column": 2, "sticky": "e", "padx": 5, "pady": 2},
            ],

            # 行 3: 随机算法选择（三个控件同行）
            [
                {"type": "label", "text": "随机模式算法:", "column": 0,
                 "sticky": "w", "padx": 5, "pady": 2},
                {"type": "combobox", "name": "rng_combo", "column": 1,
                 "sticky": "w", "padx": 5, "pady": 2,
                 "textvariable": self.rng_var, "values": list(RNG_ID.keys()), "width": 18},
                {"type": "label", "text": "（仅当偏移框为空时生效）", "column": 2,
                 "sticky": "w", "padx": 5, "fg": "gray"},
            ],

            # 行 4: 嵌入参数选项（占整行）
            [{"type": "checkbutton", "name": "embed_check", "column": 0,
              "columnspan": 3, "sticky": "w", "padx": 5, "pady": 5,
              "text": "将加密参数嵌入密文头部（自动解密，强烈推荐）",
              "variable": self.embed_var}],

            # 行 5: 输入编码（三个控件同行）
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

            # 行 6: 密钥（三个控件同行）
            [
                {"type": "label", "text": "密钥字符串 (UTF-8)", "column": 0,
                 "sticky": "w", "padx": 5, "pady": 2},
                {"type": "entry", "name": "key_entry", "column": 1,
                 "sticky": "ew", "padx": 5, "pady": 2},
                {"type": "button", "text": "生成随机密钥", "command": self.generate_random_key,
                 "column": 2, "sticky": "w", "padx": 5, "pady": 2},
            ],

            # 行 7: Base64 输出（占整行）
            [{"type": "checkbutton", "name": "base64_check", "column": 0,
              "columnspan": 3, "sticky": "w", "padx": 5, "pady": 5,
              "text": "Base64 输出 (推荐)", "variable": self.base64_var}],

            # 行 8: 结果标签
            [{"type": "label", "text": "结果", "column": 0,
              "sticky": "w", "padx": 5, "pady": 2}],

            # 行 9: 结果文本框（占三列）—— 对应 weight=1
            [{"type": "scrolledtext", "name": "output_text", "column": 0,
              "columnspan": 3, "sticky": "nsew", "padx": 5, "pady": 5,
              "height": 5, "wrap": tk.WORD}],

            # 行 10: 状态栏（占整行）
            [{"type": "status", "name": "status", "column": 0,
              "columnspan": 3, "sticky": "we", "padx": 5, "pady": 2,
              "text": "就绪", "fg": "green"}],
        ]

        root = self.root

        # 遍历按行分组的配置，自动分配行号
        for row_idx, row_items in enumerate(row_configs):
            for item in row_items:
                item["row"] = row_idx
                widget = self._make_widget(item)
                #  将带 name 的控件绑定为实例属性
                if "name" in item:
                    setattr(self, item["name"], widget)
                # 提取 grid 参数并布局
                grid_kw = {k: item[k] for k in ("row", "column", "sticky", "padx", "pady",
                                                "columnspan", "rowspan") if k in item}
                widget.grid(**grid_kw)

        # ---------- 按钮框架（独立创建，保持布局灵活） ----------
        btn_frame = tk.Frame(root)
        btn_frame.grid(row=8, column=0, columnspan=3, pady=10, sticky="ew")
        tk.Button(btn_frame, text="加密", command=self.do_encrypt, width=10).pack(side="left", padx=5)
        tk.Button(btn_frame, text="解密", command=self.do_decrypt, width=10).pack(side="left", padx=5)
        tk.Button(btn_frame, text="清空", command=self.clear_all, width=10).pack(side="left", padx=5)
        tk.Button(btn_frame, text="查看错误日志", command=self.show_check, width=12).pack(side="left", padx=5)

    def _make_widget(self, cfg: dict):
        """控件工厂：根据配置字典创建对应的 tkinter 控件。"""
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

    # ==================== 核心功能方法 ====================
    def generate_random_key(self):
        """生成随机密钥并填入密钥框"""
        key = secrets.token_urlsafe(32)
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key)
        self.status.config(text="已生成随机密钥，请妥善保存", fg="blue")

    def log_error(self, msg: str):
        """记录错误日志（时间戳 + 消息）"""
        entry = {"time": time.strftime("%H:%M:%S"), "msg": msg}
        self.logs.append(entry)
        if len(self.logs) > self.max_logs:
            self.logs = self.logs[-self.max_logs:]
        if self.check_window and self.check_window.winfo_exists():
            self.refresh_check_window()

    def do_encrypt(self):
        """执行加密操作"""
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
            embed = self.embed_var.get()
            offset_str = self.offset_entry.get().strip()
            rng_id = RNG_ID.get(self.rng_var.get(), 0)

            packet = encrypt_with_offset(plain, offset_str, key_str, input_enc,
                                         embed_params=embed, rng_id=rng_id,
                                         error_log=self.log_error)

            if self.base64_var.get():
                output = base64.b64encode(packet).decode('ascii')
            else:
                output = packet.hex()
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", output)
            self.status.config(text="加密成功", fg="green")
        except Exception as e:
            err_msg = f"加密失败: {str(e)}"
            self.log_error(err_msg)
            messagebox.showerror("错误", err_msg)
            self.status.config(text="加密失败", fg="red")

    def do_decrypt(self):
        """执行解密操作"""
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
            embed = self.embed_var.get()
            offset_str = self.offset_entry.get().strip()

            try:
                packet = base64.b64decode(b64.encode('ascii'))
            except Exception as e:
                raise ValueError(f"Base64 解码失败: {e}")

            plain = decrypt_with_offset(packet, offset_str, key_str, input_enc,
                                        embed_params=embed, error_log=self.log_error)

            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", plain)
            self.status.config(text="解密成功", fg="green")
        except Exception as e:
            err_msg = f"解密失败: {str(e)}"
            self.log_error(err_msg)
            messagebox.showerror("错误", err_msg)
            self.status.config(text="解密失败", fg="red")

    def clear_all(self):
        """清空输入和输出框"""
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)
        self.status.config(text="已清空", fg="blue")

    # ==================== 生成偏移弹出窗口 ====================
    def generate_offset_popup(self):
        """弹出窗口，用于生成偏移序列并自动填入"""
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

    # ==================== 错误日志查看窗口 ====================
    def show_check(self):
        """显示错误日志窗口"""
        if self.check_window and self.check_window.winfo_exists():
            self.check_window.lift()
            self.refresh_check_window()
            return
        self.check_window = tk.Toplevel(self.root)
        self.check_window.title("错误日志")
        self.check_window.geometry("700x400")
        self.check_window.resizable(True, True)
        self.check_window.protocol("WM_DELETE_WINDOW", self.on_check_close)

        toolbar = tk.Frame(self.check_window)
        toolbar.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        tk.Button(toolbar, text="清空日志", command=self.clear_logs).pack(side=tk.LEFT, padx=2)
        tk.Button(toolbar, text="复制全部", command=self.copy_all_logs).pack(side=tk.LEFT, padx=2)

        tree_frame = tk.Frame(self.check_window)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL)
        hsb = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL)
        self.tree = ttk.Treeview(tree_frame, columns=("时间", "错误信息"),
                                 show="tree headings",
                                 yscrollcommand=vsb.set,
                                 xscrollcommand=hsb.set)
        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)

        self.tree.heading("#0", text="序号")
        self.tree.heading("时间", text="时间")
        self.tree.heading("错误信息", text="错误信息")
        self.tree.column("#0", width=50, minwidth=50, stretch=False)
        self.tree.column("时间", width=80, minwidth=80, stretch=False)
        self.tree.column("错误信息", width=500, minwidth=200, stretch=True)

        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')

        self.view_mode = "group"
        self.refresh_check_window()

    def refresh_check_window(self):
        """刷新错误日志列表"""
        if not self.check_window or not self.check_window.winfo_exists():
            return
        for item in self.tree.get_children():
            self.tree.delete(item)
        for idx, entry in enumerate(self.logs, 1):
            self.tree.insert("", tk.END, text=str(idx),
                             values=(entry["time"], entry["msg"]))

    def clear_logs(self):
        """清空错误日志"""
        self.logs.clear()
        self.refresh_check_window()

    def copy_all_logs(self):
        """复制全部日志到剪贴板"""
        if not self.logs:
            messagebox.showinfo("提示", "日志为空")
            return
        lines = [f"{entry['time']}  {entry['msg']}" for entry in self.logs]
        text = "\n".join(lines)
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()
        messagebox.showinfo("复制成功", "已复制全部日志到剪贴板")

    def on_check_close(self):
        """关闭日志窗口时的清理"""
        self.check_window.destroy()
        self.check_window = None


# ================ 程序入口 ===================
def main():
    root = tk.Tk()
    app = OffsetEncryptApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()