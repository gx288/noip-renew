#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
No-IP Auto Renewer (Upgraded from moebiuss/noip-renew & loblab/noip-renew)
- Supports Headless Chromium + Selenium 4
- Supports TOTP 2FA (NOIP_2FA_SECRET_KEY / pyotp)
- Supports both No-IP 2026 New UI (/dns/records) and Legacy UI (/dynamic-dns)
- Includes HTTP Session + HTMX AJAX fallback engine
- Captures screenshots at each step and sends results to Telegram
"""

import os
import re
import sys
import time
import json
import base64
from datetime import datetime, timezone, timedelta
from string import Template

import pyotp
import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from selenium import webdriver
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# Fix Windows console encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

load_dotenv()

VERSION = "3.0.0"
VIETNAM_TZ = timezone(timedelta(hours=7))


def get_vn_time() -> str:
    return datetime.now(VIETNAM_TZ).strftime("%Y-%m-%d %H:%M:%S")


class Logger:
    def __init__(self, level: int = 1):
        self.level = 1 if level is None else int(level)
        self.logs = []

    def log(self, msg: str, level: int = 1):
        ts = get_vn_time()
        line = f"[{ts}] {msg}"
        self.logs.append(line)
        if self.level >= level:
            print(line, flush=True)


class TelegramNotifier:
    def __init__(self, bot_token: str, chat_id: str, logger: Logger):
        self.bot_token = (bot_token or "").strip()
        self.chat_id = (chat_id or "").strip()
        self.logger = logger

    @property
    def enabled(self) -> bool:
        return bool(self.bot_token and self.chat_id)

    def send_report(self, caption: str, photo_path: str = None):
        if not self.enabled:
            self.logger.log("Telegram chưa cấu hình TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID, bỏ qua gửi thông báo.")
            return

        try:
            if photo_path and os.path.exists(photo_path):
                url = f"https://api.telegram.org/bot{self.bot_token}/sendPhoto"
                with open(photo_path, "rb") as f:
                    resp = requests.post(
                        url,
                        data={
                            "chat_id": self.chat_id,
                            "caption": caption[:1024],
                            "parse_mode": "HTML",
                        },
                        files={"photo": f},
                        timeout=30,
                    )
                if resp.status_code == 200:
                    self.logger.log("Đã gửi thông báo kèm ảnh chụp màn hình qua Telegram.")
                    return
                else:
                    self.logger.log(f"Gửi ảnh Telegram thất bại ({resp.status_code}): {resp.text}")

            # Fallback to text message
            url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
            resp = requests.post(
                url,
                json={
                    "chat_id": self.chat_id,
                    "text": caption[:4096],
                    "parse_mode": "HTML",
                },
                timeout=30,
            )
            if resp.status_code == 200:
                self.logger.log("Đã gửi tin nhắn kết quả qua Telegram.")
            else:
                self.logger.log(f"Gửi tin nhắn Telegram thất bại ({resp.status_code}): {resp.text}")
        except Exception as e:
            self.logger.log(f"Lỗi khi gửi Telegram: {e}")


class NoIPRobot:
    USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    )
    LOGIN_URL = "https://www.noip.com/login"
    VERIFY_URL = "https://www.noip.com/2fa/verify"
    DNS_RECORDS_URL = "https://my.noip.com/dns/records"
    DYNAMIC_DNS_URL = "https://my.noip.com/dynamic-dns"
    LOGOUT_URL = "https://my.noip.com/auth/logout"
    TOUCH_URL_TEMPLATE = Template("https://my.noip.com/ajax/host/$id/touch")

    def __init__(
        self,
        username: str,
        password: str,
        totp_secret: str,
        debug: int = 1,
        notifier: TelegramNotifier = None,
    ):
        self.username = username.strip()
        self.password = password
        # Normalize 2FA secret key (remove spaces, uppercase)
        self.totp_secret = re.sub(r"\s+", "", totp_secret.strip()).upper()
        self.debug = int(debug)
        self.logger = Logger(self.debug)
        self.notifier = notifier
        self.browser = None
        self.host_statuses = []  # List of dicts: {name, days, status, renewed}
        self.confirmed_count = 0

    def init_browser(self):
        options = webdriver.ChromeOptions()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument("--disable-features=VizDisplayCompositor")
        options.add_argument("--window-size=1440,1080")
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_argument(f"--user-agent={self.USER_AGENT}")

        if "https_proxy" in os.environ and os.environ["https_proxy"]:
            options.add_argument("proxy-server=" + os.environ["https_proxy"])

        browser = webdriver.Chrome(options=options)
        browser.set_page_load_timeout(90)
        return browser

    def get_totp_code(self) -> str:
        totp = pyotp.TOTP(self.totp_secret)
        # If current TOTP window has < 3 seconds left, wait for next window to avoid race error
        time_remaining = totp.interval - (time.time() % totp.interval)
        if time_remaining < 3:
            self.logger.log(f"Đợi {time_remaining:.1f}s để lấy mã 2FA chu kỳ mới...")
            time.sleep(time_remaining + 0.5)
        return totp.now()

    def login(self):
        self.logger.log(f"Đang mở trang đăng nhập {self.LOGIN_URL}...")
        self.browser.get(self.LOGIN_URL)

        try:
            WebDriverWait(self.browser, 20).until(
                EC.presence_of_element_located((By.NAME, "username"))
            )
        except TimeoutException:
            self.browser.save_screenshot("debug_login_load_fail.png")
            raise RuntimeError("Không thể tải trang đăng nhập No-IP (Timeout).")

        if self.debug > 1:
            self.browser.save_screenshot("debug1_login_page.png")

        # Dismiss cookie banner if present
        try:
            cookie_btns = self.browser.find_elements(
                By.XPATH,
                "//button[contains(translate(., 'ACCEPT', 'accept'), 'accept') or contains(@id, 'cookie')]",
            )
            for btn in cookie_btns:
                if btn.is_displayed():
                    btn.click()
                    time.sleep(0.5)
                    break
        except Exception:
            pass

        self.logger.log(f"Đang đăng nhập tài khoản: {self.username}...")
        ele_usr = self.browser.find_element(By.NAME, "username")
        ele_pwd = self.browser.find_element(By.NAME, "password")

        ele_usr.clear()
        ele_usr.send_keys(self.username)
        ele_pwd.clear()
        ele_pwd.send_keys(self.password)

        # Click login button or press Enter
        try:
            login_btn = self.browser.find_element(By.ID, "clogs-captcha-button")
            login_btn.click()
        except NoSuchElementException:
            ele_pwd.send_keys(Keys.ENTER)

        # Wait for 2FA page or dashboard
        time.sleep(2)
        try:
            WebDriverWait(self.browser, 25).until(
                lambda d: "2fa" in d.current_url
                or len(d.find_elements(By.ID, "verificationCode")) > 0
                or len(d.find_elements(By.NAME, "challenge_code")) > 0
                or "my.noip.com" in d.current_url
            )
        except TimeoutException:
            self.browser.save_screenshot("debug_after_login_timeout.png")
            raise RuntimeError(
                f"Đăng nhập không chuyển hướng sang trang 2FA/Dashboard (URL hiện tại: {self.browser.current_url}). Kiểm tra lại Username/Password."
            )

        if "2fa" in self.browser.current_url or len(self.browser.find_elements(By.ID, "verificationCode")) > 0 or len(self.browser.find_elements(By.NAME, "challenge_code")) > 0:
            self.handle_2fa()
        else:
            self.logger.log("Không yêu cầu bước 2FA, đã vào thẳng Dashboard.")

        # Wait for my.noip.com dashboard
        try:
            WebDriverWait(self.browser, 30).until(
                lambda d: "my.noip.com" in d.current_url
                or len(d.find_elements(By.ID, "noip-cart")) > 0
                or len(d.find_elements(By.ID, "main-wrapper")) > 0
            )
            self.logger.log("Đăng nhập thành công vào my.noip.com!")
        except TimeoutException:
            self.browser.save_screenshot("debug_dashboard_timeout.png")
            raise RuntimeError("Không thể tải trang quản trị my.noip.com sau khi xác thực 2FA.")

        if self.debug > 1:
            self.browser.save_screenshot("debug2_dashboard.png")

    def handle_2fa(self):
        if self.debug > 1:
            self.browser.save_screenshot("debug_otp_page.png")

        otp_code = self.get_totp_code()
        self.logger.log("Đang nhập mã xác thực 2FA (TOTP)...")

        # Case 1: 6 individual digit inputs inside #totp-input / #otp-input / #verificationCode (No-IP 2026 UI)
        otp_boxes = self.browser.find_elements(
            By.CSS_SELECTOR,
            "#totp-input input, #otp-input input, #verificationCode input[type='number'], #verificationCode input[type='text']",
        )
        visible_boxes = [b for b in otp_boxes if b.is_displayed()]

        if len(visible_boxes) >= 6:
            for i in range(6):
                try:
                    visible_boxes[i].clear()
                except Exception:
                    pass
                visible_boxes[i].send_keys(otp_code[i])
            # Also ensure hidden #challenge_code is populated
            self.browser.execute_script(
                "var el = document.getElementById('challenge_code'); if (el) el.value = arguments[0];",
                otp_code,
            )
        else:
            # Case 2: Single visible input field (challenge_code)
            challenge_inputs = self.browser.find_elements(By.NAME, "challenge_code")
            if challenge_inputs:
                ele_challenge = challenge_inputs[0]
                if ele_challenge.is_displayed():
                    self.browser.execute_script("arguments[0].focus();", ele_challenge)
                    try:
                        ele_challenge.clear()
                        ele_challenge.send_keys(otp_code)
                    except Exception:
                        ActionChains(self.browser).send_keys(otp_code).perform()
                else:
                    self.browser.execute_script("arguments[0].value = arguments[1];", ele_challenge, otp_code)
                    ActionChains(self.browser).send_keys(otp_code).perform()
            else:
                ActionChains(self.browser).send_keys(otp_code).perform()

        time.sleep(0.5)
        # Submit 2FA form
        submit_btns = self.browser.find_elements(
            By.CSS_SELECTOR, "#verificationCode input[name='submit'], #verificationCode button[type='submit']"
        )
        if not submit_btns:
            submit_btns = [
                b for b in self.browser.find_elements(By.NAME, "submit") if b.is_displayed()
            ]
        if submit_btns:
            submit_btns[0].click()
        else:
            ActionChains(self.browser).send_keys(Keys.ENTER).perform()

    def update_hosts(self) -> bool:
        """
        Check both the new DNS Records page (/dns/records) and classic Dynamic DNS page (/dynamic-dns)
        so all UI versions of No-IP are supported.
        """
        self.logger.log(f"Đang kiểm tra danh sách tên miền tại {self.DNS_RECORDS_URL}...")
        self.browser.get(self.DNS_RECORDS_URL)
        time.sleep(5)

        handled = False

        # 1. Check New UI (#zone-collection-wrapper)
        zone_wrappers = self.browser.find_elements(By.ID, "zone-collection-wrapper")
        if zone_wrappers:
            self.logger.log("Phát hiện giao diện No-IP mới (zone-collection-wrapper).")
            handled = self._process_new_ui()

        # 2. Check Legacy UI (/dynamic-dns table) if no hosts found yet
        if not handled or len(self.host_statuses) == 0:
            self.logger.log(f"Đang kiểm tra trang {self.DYNAMIC_DNS_URL}...")
            self.browser.get(self.DYNAMIC_DNS_URL)
            time.sleep(5)
            host_tds = self.browser.find_elements(By.XPATH, "//td[@data-title='Host']")
            if host_tds:
                self.logger.log(f"Phát hiện giao diện bảng Dynamic DNS ({len(host_tds)} tên miền).")
                self._process_legacy_ui()
                handled = True
            elif len(self.browser.find_elements(By.ID, "zone-collection-wrapper")) > 0 and not self.host_statuses:
                self._process_new_ui()
                handled = True
        else:
            # Return to /dns/records for the final screenshot if we already processed new UI
            if "dns/records" not in self.browser.current_url:
                self.browser.get(self.DNS_RECORDS_URL)
                time.sleep(3)

        # Save final results screenshot
        self.browser.save_screenshot("results.png")
        self.logger.log(f"Hoàn tất kiểm tra. Số host đã xác nhận gia hạn: {self.confirmed_count}")
        return True

    def _process_new_ui(self) -> bool:
        """
        Process No-IP 2025/2026 New UI (#zone-collection-wrapper)
        """
        # Find any expiration banners requiring confirmation
        banners = self.browser.find_elements(
            By.XPATH, "//*[starts-with(@id, 'expiration-banner-hostname-')]"
        )

        if banners:
            self.logger.log(f"Tìm thấy {len(banners)} tên miền cần xác nhận gia hạn ngay!")
            for idx in range(len(banners)):
                # Re-fetch banners after DOM updates
                current_banners = self.browser.find_elements(
                    By.XPATH, "//*[starts-with(@id, 'expiration-banner-hostname-')]"
                )
                if not current_banners:
                    break
                banner = current_banners[0]
                banner_text = banner.text.strip()
                host_name = "Unknown Host"
                days_left = None

                # Parse "Expires in X days - example.ddns.net"
                m_days = re.search(r"Expires in\s+(\d+)\s+days?", banner_text, re.IGNORECASE)
                if m_days:
                    days_left = int(m_days.group(1))

                try:
                    h4 = banner.find_element(By.TAG_NAME, "h4")
                    host_name = re.sub(r"Expires in \d+ days?\s*-\s*", "", h4.text, flags=re.IGNORECASE).strip()
                except NoSuchElementException:
                    pass

                # Find Confirm button inside banner
                confirmed_this = False
                buttons = banner.find_elements(By.TAG_NAME, "button")
                if not buttons:
                    buttons = banner.find_elements(By.XPATH, ".//*[contains(translate(text(), 'CONFIRM', 'confirm'), 'confirm')]")
                for btn in buttons:
                    if "confirm" in btn.text.lower() or btn.get_attribute("hx-get"):
                        self.logger.log(f"Đang bấm Confirm gia hạn cho: {host_name}...")
                        self.browser.execute_script("arguments[0].scrollIntoView({block: 'center'});", btn)
                        time.sleep(0.5)
                        try:
                            btn.click()
                        except Exception:
                            self.browser.execute_script("arguments[0].click();", btn)
                        time.sleep(3)
                        self.confirmed_count += 1
                        confirmed_this = True
                        self.browser.save_screenshot(f"{host_name}_success.png")
                        break

                # Fallback: Direct HTMX AJAX touch inside browser session if button click didn't work
                if not confirmed_this:
                    soup_cur = BeautifulSoup(self.browser.page_source, "html.parser")
                    host_tag = soup_cur.select_one('[data-label^="host="]')
                    if host_tag:
                        host_id = host_tag["data-label"].replace("host=", "").strip()
                        touch_url = self.TOUCH_URL_TEMPLATE.substitute(id=host_id)
                        self.logger.log(f"Đang gọi AJAX gia hạn cho host ID {host_id} ({host_name})...")
                        res_js = self.browser.execute_script(
                            "return fetch(arguments[0], {headers: {'HX-Request': 'true'}}).then(r => r.json()).catch(e => ({}));",
                            touch_url,
                        )
                        if isinstance(res_js, dict) and res_js.get("success"):
                            self.confirmed_count += 1
                            confirmed_this = True
                            self.browser.save_screenshot(f"{host_name}_success.png")

                self.host_statuses.append({
                    "name": host_name,
                    "days": 30 if confirmed_this else (days_left or "?"),
                    "renewed": confirmed_this,
                    "note": "Đã bấm Confirm gia hạn thành công (+30 ngày)" if confirmed_this else "Cần kiểm tra thủ công",
                })

                # Refresh page for next banner if multiple
                self.browser.get(self.DNS_RECORDS_URL)
                time.sleep(4)

        # Collect all active hosts on the page for reporting
        soup = BeautifulSoup(self.browser.page_source, "html.parser")
        existing_names = {h["name"] for h in self.host_statuses}

        for row in soup.select(".zone-record"):
            fqdn_el = row.select_one("[data-fqdm]")
            fqdn = fqdn_el.get("data-fqdm", "").strip() if fqdn_el else ""
            if not fqdn:
                d_name = row.get("data-name", "").strip()
                d_zone = row.get("data-zone", "").strip()
                if d_name and d_zone:
                    fqdn = f"{d_name}.{d_zone}"
            if fqdn and fqdn not in existing_names:
                existing_names.add(fqdn)
                last_update = row.get("data-update", "").strip()
                row_text = " ".join(row.get_text().split())
                ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", row_text)
                ip_str = f"IP: {ip_match.group(0)}" if ip_match else ""
                extra = " | ".join(filter(None, [ip_str, f"Cập nhật: {last_update}" if last_update else ""]))
                note = "Đang hoạt động tốt (chưa đến kỳ mở nút Confirm <= 7 ngày)"
                if extra:
                    note = f"{extra} — {note}"
                self.host_statuses.append({
                    "name": fqdn,
                    "days": "> 7",
                    "renewed": False,
                    "note": note,
                })

        return True

    def _process_legacy_ui(self):
        """
        Process Classic No-IP Dynamic DNS table (//td[@data-title='Host'])
        """
        hosts = self.browser.find_elements(By.XPATH, "//td[@data-title='Host']")
        iteration = 1

        for host in hosts:
            try:
                host_link = host.find_element(
                    By.XPATH, ".//a[contains(@class, 'link-info') or contains(@class, 'cursor-pointer')]"
                )
                host_name = host_link.text.strip()
            except NoSuchElementException:
                host_name = host.text.strip().split("\n")[0]

            expiration_days = self._get_legacy_expiration_days(host, iteration)
            self.logger.log(f"Host: {host_name} - Còn lại: {expiration_days} ngày")

            if expiration_days <= 7:
                host_button = self._get_legacy_host_button(host)
                if host_button:
                    self._click_legacy_host_button(host_button, host_name)
                    new_days = self._get_legacy_expiration_days(host, iteration)
                    self.confirmed_count += 1
                    self.host_statuses.append({
                        "name": host_name,
                        "days": new_days if new_days > expiration_days else 30,
                        "renewed": True,
                        "note": f"Đã gia hạn thành công (trước đó còn {expiration_days} ngày)",
                    })
                else:
                    self.host_statuses.append({
                        "name": host_name,
                        "days": expiration_days,
                        "renewed": False,
                        "note": "Còn <= 7 ngày nhưng không tìm thấy nút Confirm",
                    })
            else:
                self.host_statuses.append({
                    "name": host_name,
                    "days": expiration_days,
                    "renewed": False,
                    "note": f"Chưa cần gia hạn (còn {expiration_days} ngày, No-IP mở nút khi <= 7 ngày)",
                })
            iteration += 1

    @staticmethod
    def _get_legacy_expiration_days(host, iteration: int) -> int:
        try:
            host_remaining_days = host.find_element(By.XPATH, ".//a[contains(@class, 'no-link-style')]")
        except NoSuchElementException:
            return 30
        title_attr = host_remaining_days.get_attribute("data-original-title")
        target_text = title_attr if title_attr is not None else host_remaining_days.text
        regex_match = re.search(r"\d+", target_text or "")
        if regex_match is None:
            return 30
        return int(regex_match.group(0))

    @staticmethod
    def _get_legacy_host_button(host):
        try:
            # Find the confirm button inside the same table row (fixes multi-host bug in original script)
            return host.find_element(By.XPATH, "./ancestor::tr//button[contains(@class, 'btn-success')]")
        except NoSuchElementException:
            try:
                return host.find_element(By.XPATH, "//td[6]/button[contains(@class, 'btn-success')]")
            except NoSuchElementException:
                return None

    def _click_legacy_host_button(self, host_button, host_name: str):
        self.logger.log(f"Đang bấm nút Confirm cho host: {host_name}...")
        host_button.click()
        time.sleep(3)
        try:
            h2s = self.browser.find_elements(By.XPATH, "//h2[@class='big']")
            if h2s and h2s[0].text.strip() == "Upgrade Now":
                raise RuntimeError("No-IP yêu cầu can thiệp thủ công (Phát hiện thông báo Upgrade Now).")
        except RuntimeError:
            raise
        except Exception:
            pass
        self.browser.save_screenshot(f"{host_name}_success.png")

    def build_summary_message(self, success: bool, error_msg: str = "") -> str:
        import html as html_lib
        status_header = "✅ <b>NO-IP AUTO RENEW: THÀNH CÔNG</b>" if success else "❌ <b>NO-IP AUTO RENEW: CÓ LỖI</b>"
        lines = [
            status_header,
            f"🕒 <b>Thời gian:</b> <code>{get_vn_time()}</code> (GMT+7)",
            f"👤 <b>Tài khoản:</b> <code>{html_lib.escape(self.username)}</code>",
        ]

        if success:
            lines.append(f"🔄 <b>Số tên miền vừa gia hạn:</b> <b>{self.confirmed_count}</b>")
            if self.host_statuses:
                lines.append("\n🌐 <b>Danh sách Hostname:</b>")
                for h in self.host_statuses:
                    icon = "✅" if h["renewed"] else "🟢"
                    h_name = html_lib.escape(str(h["name"]))
                    h_days = html_lib.escape(str(h["days"]))
                    h_note = html_lib.escape(str(h["note"]))
                    lines.append(
                        f"{icon} <code>{h_name}</code> — Còn: <b>{h_days} ngày</b>\n   └ <i>{h_note}</i>"
                    )
            else:
                lines.append("ℹ️ <i>Đã kiểm tra trang quản trị, hiện không có tên miền nào sắp hết hạn (&lt;= 7 ngày).</i>")
        else:
            short_err = html_lib.escape(str(error_msg).splitlines()[0] if error_msg else "Unknown error")
            lines.append(f"⚠️ <b>Chi tiết lỗi:</b> <code>{short_err}</code>")

        return "\n".join(lines)

    def run(self) -> int:
        rc = 0
        self.logger.log(f"=== Khởi chạy No-IP Auto Renew v{VERSION} ===")
        screenshot_to_send = "results.png"

        try:
            self.browser = self.init_browser()
            self.login()
            self.update_hosts()
            msg = self.build_summary_message(success=True)
            if self.notifier:
                self.notifier.send_report(msg, photo_path=screenshot_to_send)
        except Exception as e:
            err_str = str(e)
            self.logger.log(f"LỖI: {err_str}")
            screenshot_to_send = "exception.png"
            if self.browser:
                try:
                    self.browser.save_screenshot(screenshot_to_send)
                except Exception:
                    pass
            msg = self.build_summary_message(success=False, error_msg=err_str)
            if self.notifier:
                self.notifier.send_report(msg, photo_path=screenshot_to_send)
            rc = 2
        finally:
            if self.browser:
                try:
                    self.browser.get(self.LOGOUT_URL)
                except Exception:
                    pass
                try:
                    self.browser.quit()
                except Exception:
                    pass
        return rc


def main(argv=None):
    if argv is None:
        argv = sys.argv

    # Prefer environment variables (GitHub Actions / Docker / .env)
    username = os.environ.get("NOIP_USERNAME", "").strip()
    password = os.environ.get("NOIP_PASSWORD", "").strip()
    totp_secret = (
        os.environ.get("NOIP_2FA_SECRET_KEY", "").strip()
        or os.environ.get("NOIP_TOTP_SECRET", "").strip()
    )
    debug = int(os.environ.get("NOIP_DEBUG", "1") or "1")

    # Fallback to CLI arguments (compatible with original loblab/moebiuss CLI)
    if (not username or not password or not totp_secret) and len(argv) >= 4:
        username = argv[1]
        try:
            password = base64.b64decode(argv[2]).decode("utf-8")
        except Exception:
            password = argv[2]
        totp_secret = argv[3]
        if len(argv) > 4:
            debug = int(argv[4])

    if not username or not password or not totp_secret:
        print(
            "❌ Thiếu thông tin cấu hình! Vui lòng thiết lập biến môi trường:\n"
            "  - NOIP_USERNAME\n"
            "  - NOIP_PASSWORD\n"
            "  - NOIP_2FA_SECRET_KEY\n"
            "(Hoặc truyền qua tham số dòng lệnh: python noip_renew.py <user> <pass> <2fa_secret>)"
        )
        return 1

    bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
    logger = Logger(debug)
    notifier = TelegramNotifier(bot_token, chat_id, logger)

    robot = NoIPRobot(
        username=username,
        password=password,
        totp_secret=totp_secret,
        debug=debug,
        notifier=notifier,
    )
    return robot.run()


if __name__ == "__main__":
    sys.exit(main())
