import json
import hashlib
import smtplib
from email.mime.text import MIMEText
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import os
import logging

# 初始化日志记录
LOG_FILE = "directory_monitor.log"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")

# 文件哈希计算函数
def calculate_file_hash(file_path):
    try:
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256()
            chunk = f.read(8192)
            while chunk:
                file_hash.update(chunk)
                chunk = f.read(8192)
            return file_hash.hexdigest()
    except Exception:
        return None

# 邮件通知函数
def send_email(email_config, subject, body):
    smtp_server = email_config["smtp_server"]
    smtp_port = email_config["smtp_port"]
    sender_email = email_config["sender_email"]
    sender_password = email_config["sender_password"]
    recipient_email = email_config["recipient_email"]

    try:
        # 构造邮件
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = sender_email
        msg["To"] = recipient_email

        # 发送邮件
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
            print(f"[邮件通知] 成功发送邮件到 {recipient_email}")
    except Exception as e:
        print(f"[邮件通知] 发送邮件失败: {e}")

# 自定义事件处理类
class DirectoryMonitorHandler(FileSystemEventHandler):
    def __init__(self, monitored_dir, file_types, email_config):
        self.monitored_dir = monitored_dir
        self.file_types = file_types
        self.email_config = email_config
        self.file_hashes = {}

    # 过滤文件类型
    def _is_file_type_valid(self, file_path):
        if not self.file_types:
            return True
        return any(file_path.endswith(ext) for ext in self.file_types)

    def _log_and_notify(self, event_type, file_path, extra_info=""):
        message = f"[{event_type}] 文件: {file_path} {extra_info}"
        print(message)
        logging.info(message)

        # 关键事件发送邮件通知
        if event_type in ["删除", "重命名/移动"]:
            send_email(self.email_config, f"目录监控通知: {event_type}", message)

    # 文件创建事件
    def on_created(self, event):
        if not event.is_directory and self._is_file_type_valid(event.src_path):
            self._log_and_notify("新增", event.src_path)

    # 文件删除事件
    def on_deleted(self, event):
        if not event.is_directory and self._is_file_type_valid(event.src_path):
            self._log_and_notify("删除", event.src_path)

    # 文件修改事件
    def on_modified(self, event):
        if not event.is_directory and self._is_file_type_valid(event.src_path):
            new_hash = calculate_file_hash(event.src_path)
            old_hash = self.file_hashes.get(event.src_path)

            if new_hash and old_hash and new_hash != old_hash:
                self._log_and_notify("篡改检测", event.src_path, "文件内容被修改！")
            self.file_hashes[event.src_path] = new_hash

    # 文件重命名事件
    def on_moved(self, event):
        if not event.is_directory and self._is_file_type_valid(event.src_path):
            self._log_and_notify("重命名/移动", event.src_path, f"新路径: {event.dest_path}")


def monitor_directory(config):
    path_to_monitor = config["monitored_directory"]
    file_types = config.get("file_types", [])
    email_config = config["email_config"]

    if not os.path.exists(path_to_monitor):
        print(f"指定的路径不存在: {path_to_monitor}")
        return

    # 初始化事件处理器
    event_handler = DirectoryMonitorHandler(path_to_monitor, file_types, email_config)
    # 初始化观察者
    observer = Observer()
    observer.schedule(event_handler, path=path_to_monitor, recursive=True)

    # 启动观察者
    print(f"开始监控目录: {path_to_monitor}")
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("停止监控...")
        observer.stop()
    observer.join()


if __name__ == "__main__":
    # 加载配置文件
    config_file = "config.json"
    if not os.path.exists(config_file):
        print(f"配置文件 {config_file} 不存在！请先创建配置文件。")
    else:
        with open(config_file, "r") as f:
            config = json.load(f)
        monitor_directory(config)
