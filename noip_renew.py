#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
No-IP Auto Renewer (Upgraded from moebiuss/noip-renew & loblab/noip-renew)
- Supports Headless Chromium + Selenium 4
- Supports TOTP 2FA (NOIP_2FA_SECRET_KEY / pyotp)
- Supports both No-IP 2026 New UI (/dns/records + /ajax/host/<id>/touch) and Legacy UI (/dynamic-dns)
- Tracks exact expiration date (in_redemption_at), days remaining, and last confirmation date in renew_state.json
- Smart Telegram Notification: Only notifies when a host is confirmed/renewed, when an error/anomaly occurs,
  when a host is <= 7 days remaining (or >= 25 days since last renewal) without being renewed, or when FORCE_NOTIFY=true.
"""

import os
import re
import sys
import time
import json
import base64
import html as html_lib
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

VERSION = "3.2.0"
VIETNAM_TZ = timezone(timedelta(hours=7))
STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "renew_state.json")


def get_vn_now() -> datetime:
    return datetime.now(VIETNAM_TZ)


def get_vn_time() -> str:
    return get_vn_now().strftime("%Y-%m-%d %H:%M:%S")


def get_vn_date() -> str:
    return get_vn_now().strftime("%Y-%m-%d")


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
        force_notify: bool = False,
    ):
        self.username = username.strip()
        self.password = password
        self.totp_secret = re.sub(r"\s+", "", totp_secret.strip()).upper()
        self.debug = int(debug)
        self.logger = Logger(self.debug)
        self.notifier = notifier
        self.force_notify = force_notify
        self.browser = None
        self.host_statuses = []
        self.confirmed_count = 0
        self.has_anomaly = False
        self.anomaly_reasons = []
        self.state = self.load_state()

    def load_state(self) -> dict:
        if os.path.exists(STATE_FILE):
            try:
                with open(STATE_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {"updated_at": "", "hosts": {}}

    def save_state(self):
        self.state["updated_at"] = get_vn_time()
        try:
            with open(STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(self.state, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.logger.log(f"Không thể lưu {STATE_FILE}: {e}")

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

        try:
            login_btn = self.browser.find_element(By.ID, "clogs-captcha-button")
            login_btn.click()
        except NoSuchElementException:
            ele_pwd.send_keys(Keys.ENTER)

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

        if (
            "2fa" in self.browser.current_url
            or len(self.browser.find_elements(By.ID, "verificationCode")) > 0
            or len(self.browser.find_elements(By.NAME, "challenge_code")) > 0
        ):
            self.handle_2fa()
        else:
            self.logger.log("Không yêu cầu bước 2FA, đã vào thẳng Dashboard.")

        dashboard_loaded = False
        for attempt in range(3):
            try:
                WebDriverWait(self.browser, 25).until(
                    lambda d: (
                        "my.noip.com" in d.current_url
                        and "ERR_" not in d.page_source
                        and len(d.find_elements(By.ID, "main-frame-error")) == 0
                        and (
                            len(d.find_elements(By.ID, "zone-collection-wrapper")) > 0
                            or len(d.find_elements(By.ID, "main-wrapper")) > 0
                            or len(
                                d.find_elements(
                                    By.CSS_SELECTOR,
                                    "a[href*='/dns/records'], a[href*='/settings/security']",
                                )
                            )
                            > 0
                        )
                    )
                )
                dashboard_loaded = True
                break
            except TimeoutException:
                self.logger.log(
                    f"Lần thử {attempt + 1}/3: Chưa tải xong DOM my.noip.com (URL: {self.browser.current_url}), đang thử tải lại https://my.noip.com/dns/records..."
                )
                try:
                    self.browser.get(self.DNS_RECORDS_URL)
                    time.sleep(4)
                except Exception:
                    pass

        if not dashboard_loaded:
            self.browser.save_screenshot("debug_dashboard_timeout.png")
            raise RuntimeError(
                f"Không thể tải trang quản trị my.noip.com sau khi xác thực 2FA (URL hiện tại: {self.browser.current_url})."
            )

        self.logger.log("Đăng nhập thành công vào my.noip.com!")
        if self.debug > 1:
            self.browser.save_screenshot("debug2_dashboard.png")

    def handle_2fa(self):
        if self.debug > 1:
            self.browser.save_screenshot("debug_otp_page.png")

        otp_code = self.get_totp_code()
        self.logger.log("Đang nhập mã xác thực 2FA (TOTP)...")

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
            self.browser.execute_script(
                "var el = document.getElementById('challenge_code'); if (el) el.value = arguments[0];",
                otp_code,
            )
        else:
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
        self.logger.log(f"Đang kiểm tra danh sách tên miền tại {self.DNS_RECORDS_URL}...")
        for attempt in range(3):
            try:
                if "dns/records" not in self.browser.current_url:
                    self.browser.get(self.DNS_RECORDS_URL)
                WebDriverWait(self.browser, 20).until(
                    lambda d: len(d.find_elements(By.ID, "zone-collection-wrapper")) > 0
                    or len(d.find_elements(By.CSS_SELECTOR, ".zone-record")) > 0
                )
                time.sleep(3)
                break
            except TimeoutException:
                self.logger.log(f"Thử tải lại {self.DNS_RECORDS_URL} (lần {attempt + 1}/3)...")
                self.browser.get(self.DNS_RECORDS_URL)
                time.sleep(4)

        handled = False

        zone_wrappers = self.browser.find_elements(By.ID, "zone-collection-wrapper")
        if zone_wrappers:
            self.logger.log("Phát hiện giao diện No-IP mới (zone-collection-wrapper).")
            handled = self._process_new_ui()

        if not handled:
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

        if "login" in self.browser.current_url.lower() or not handled:
            self.browser.save_screenshot("results.png")
            raise RuntimeError(
                f"Phiên truy cập my.noip.com bị ngắt hoặc chuyển về trang Login (URL: {self.browser.current_url})."
            )

        if len(self.host_statuses) == 0:
            self.has_anomaly = True
            self.anomaly_reasons.append("Không tìm thấy bất kỳ tên miền nào trong tài khoản!")

        self.save_state()
        self.browser.save_screenshot("results.png")
        self.logger.log(f"Hoàn tất kiểm tra. Số host vừa xác nhận gia hạn: {self.confirmed_count}")
        return True

    def _fetch_host_touch_info(self, host_id: str) -> dict:
        """
        Calls https://my.noip.com/ajax/host/<id>/touch inside the authenticated browser session.
        This endpoint both touches/confirms the host (if within <= 7 days window) AND returns exact JSON metadata!
        """
        touch_url = self.TOUCH_URL_TEMPLATE.substitute(id=host_id)
        try:
            res = self.browser.execute_script(
                """
                const url = arguments[0];
                return fetch(url, {
                    headers: {'HX-Request': 'true', 'Accept': 'application/json, text/plain, */*'}
                }).then(r => r.json()).catch(e => ({}));
                """,
                touch_url,
            )
            if isinstance(res, dict) and isinstance(res.get("host"), dict):
                return res["host"]
        except Exception as e:
            self.logger.log(f"Không lấy được metadata từ {touch_url}: {e}")
        return {}

    def _process_new_ui(self) -> bool:
        confirmed_via_banner = set()

        # 1. Check any expiration banners visible on the page
        banners = self.browser.find_elements(
            By.XPATH, "//*[starts-with(@id, 'expiration-banner-hostname-')]"
        )

        if banners:
            self.logger.log(f"Tìm thấy {len(banners)} banner tên miền cần bấm Confirm gia hạn!")
            for _ in range(len(banners)):
                current_banners = self.browser.find_elements(
                    By.XPATH, "//*[starts-with(@id, 'expiration-banner-hostname-')]"
                )
                if not current_banners:
                    break
                banner = current_banners[0]
                host_name = "Unknown Host"
                try:
                    h4 = banner.find_element(By.TAG_NAME, "h4")
                    host_name = re.sub(
                        r"Expires in \d+ days?\s*-\s*", "", h4.text, flags=re.IGNORECASE
                    ).strip()
                except NoSuchElementException:
                    pass

                buttons = banner.find_elements(By.TAG_NAME, "button")
                if not buttons:
                    buttons = banner.find_elements(
                        By.XPATH, ".//*[contains(translate(text(), 'CONFIRM', 'confirm'), 'confirm')]"
                    )
                for btn in buttons:
                    if "confirm" in btn.text.lower() or btn.get_attribute("hx-get"):
                        self.logger.log(f"Đang bấm nút Confirm trên banner cho: {host_name}...")
                        self.browser.execute_script(
                            "arguments[0].scrollIntoView({block: 'center'});", btn
                        )
                        time.sleep(0.5)
                        try:
                            btn.click()
                        except Exception:
                            self.browser.execute_script("arguments[0].click();", btn)
                        time.sleep(3)
                        confirmed_via_banner.add(host_name)
                        self.browser.save_screenshot(f"{host_name}_success.png")
                        break

                self.browser.get(self.DNS_RECORDS_URL)
                time.sleep(4)

        # 2. Inspect each .zone-record and query /ajax/host/<id>/touch for exact days & auto-touch
        soup = BeautifulSoup(self.browser.page_source, "html.parser")
        hosts_state = self.state.setdefault("hosts", {})

        for row in soup.select(".zone-record"):
            fqdn_el = row.select_one("[data-fqdm]")
            fqdn = fqdn_el.get("data-fqdm", "").strip() if fqdn_el else ""
            if not fqdn:
                d_name = row.get("data-name", "").strip()
                d_zone = row.get("data-zone", "").strip()
                if d_name and d_zone:
                    fqdn = f"{d_name}.{d_zone}"
            if not fqdn:
                continue

            data_label = row.get("data-label", "")
            host_id = data_label.replace("host=", "").strip() if "host=" in data_label else ""

            prev_info = hosts_state.get(fqdn, {})
            prev_redemption_date = prev_info.get("in_redemption_at", "")
            prev_days_remaining = prev_info.get("days_remaining", 30)

            host_meta = self._fetch_host_touch_info(host_id) if host_id else {}

            if host_meta:
                days_remaining = int(host_meta.get("days_until_redemption", host_meta.get("days_remaining", 30)))
                days_until_confirm = int(host_meta.get("days_until_confirmation", max(0, days_remaining - 7)))
                in_redemption_at = host_meta.get("in_redemption_at", "N/A")
                permanent_deletion_at = host_meta.get("permanent_deletion_at", "N/A")
                is_expiring_soon = bool(host_meta.get("is_expiring_soon", False))
                is_expired = bool(host_meta.get("is_expired", False))
                target_ip = host_meta.get("target", "")
                last_ip_update = host_meta.get("last_action_date_time", row.get("data-update", ""))
                create_date = host_meta.get("create_date", "")

                # Detect if host was just renewed in this run
                renewed_now = (
                    fqdn in confirmed_via_banner
                    or (prev_redemption_date and in_redemption_at != prev_redemption_date)
                    or (days_remaining > prev_days_remaining + 2)
                )

                if renewed_now:
                    self.confirmed_count += 1
                    last_confirmed_date = get_vn_date()
                else:
                    # Estimate last confirmed date if not stored yet (30-day cycle before in_redemption_at)
                    last_confirmed_date = prev_info.get("last_confirmed_date", "2026-10-25")

                # Calculate days elapsed since last confirmation
                days_since_last_confirm = 30 - days_remaining
                try:
                    dt_last = datetime.strptime(last_confirmed_date, "%Y-%m-%d").date()
                    days_since_last_confirm = max(days_since_last_confirm, (get_vn_now().date() - dt_last).days)
                except Exception:
                    pass

                # Check for anomalies:
                # - Host is expired or expiring soon (<= 7 days left) and STILL not renewed after touch/click!
                # - Or >= 25 days since last confirmation without renewal
                if is_expired or (is_expiring_soon and not renewed_now) or (days_remaining <= 7 and not renewed_now):
                    self.has_anomaly = True
                    self.anomaly_reasons.append(
                        f"Tên miền {fqdn} đã vào hạn cần Confirm (còn {days_remaining} ngày, hạn {in_redemption_at}) nhưng chưa gia hạn được!"
                    )
                elif days_since_last_confirm >= 25 and not renewed_now:
                    self.has_anomaly = True
                    self.anomaly_reasons.append(
                        f"Tên miền {fqdn} đã qua {days_since_last_confirm} ngày kể từ lần renew cuối ({last_confirmed_date}) mà chưa được gia hạn!"
                    )

                hosts_state[fqdn] = {
                    "host_id": host_id,
                    "target_ip": target_ip,
                    "create_date": create_date,
                    "last_ip_update": last_ip_update,
                    "last_confirmed_date": last_confirmed_date,
                    "days_remaining": days_remaining,
                    "days_until_confirmation": days_until_confirm,
                    "in_redemption_at": in_redemption_at,
                    "permanent_deletion_at": permanent_deletion_at,
                    "is_expiring_soon": is_expiring_soon,
                    "is_expired": is_expired,
                }

                if renewed_now:
                    note = (
                        f"🎉 ĐÃ GIA HẠN THÀNH CÔNG! Hạn mới: {in_redemption_at} "
                        f"(IP: {target_ip} | Mở Confirm kỳ tới sau {days_until_confirm} ngày)"
                    )
                else:
                    note = (
                        f"Renew gần nhất: {last_confirmed_date} (đã qua {days_since_last_confirm} ngày) | "
                        f"Hạn 30 ngày: {in_redemption_at} | Mở nút Confirm sau: {days_until_confirm} ngày nữa | "
                        f"IP: {target_ip}"
                    )

                self.logger.log(f"Host: {fqdn} | Còn {days_remaining} ngày | {note}")
                self.host_statuses.append({
                    "name": fqdn,
                    "days": days_remaining,
                    "renewed": renewed_now,
                    "note": note,
                })
            else:
                # Fallback if AJAX metadata unavailable
                last_update = row.get("data-update", "").strip()
                row_text = " ".join(row.get_text().split())
                ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", row_text)
                ip_str = f"IP: {ip_match.group(0)}" if ip_match else ""
                renewed_now = fqdn in confirmed_via_banner
                if renewed_now:
                    self.confirmed_count += 1
                note = f"{ip_str} | Cập nhật IP: {last_update}"
                self.host_statuses.append({
                    "name": fqdn,
                    "days": 30 if renewed_now else "> 7",
                    "renewed": renewed_now,
                    "note": note,
                })

        return True

    def _process_legacy_ui(self):
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
                    self.has_anomaly = True
                    self.anomaly_reasons.append(
                        f"Tên miền {host_name} còn {expiration_days} ngày nhưng không tìm thấy nút Confirm!"
                    )
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
        if not success:
            status_header = "❌ <b>CẢNH BÁO LỖI NO-IP AUTO RENEW</b>"
        elif self.has_anomaly:
            status_header = "⚠️ <b>CẢNH BÁO BẤT THƯỜNG / QUÁ HẠN NO-IP</b>"
        elif self.confirmed_count > 0:
            status_header = "🎉 <b>NO-IP AUTO RENEW: ĐÃ GIA HẠN THÀNH CÔNG (+30 NGÀY)</b>"
        else:
            status_header = "✅ <b>NO-IP AUTO RENEW: KIỂM TRA ĐỊNH KỲ</b>"

        lines = [
            status_header,
            f"🕒 <b>Thời gian:</b> <code>{get_vn_time()}</code> (GMT+7)",
            f"👤 <b>Tài khoản:</b> <code>{html_lib.escape(self.username)}</code>",
        ]

        if self.anomaly_reasons:
            lines.append("\n🚨 <b>Phát hiện bất thường cần kiểm tra:</b>")
            for reason in self.anomaly_reasons:
                lines.append(f"• <b>{html_lib.escape(reason)}</b>")

        if success:
            lines.append(f"🔄 <b>Số tên miền vừa Confirm:</b> <b>{self.confirmed_count}</b>")
            if self.host_statuses:
                lines.append("\n🌐 <b>Chi tiết Hostname:</b>")
                for h in self.host_statuses:
                    icon = "✅" if h["renewed"] else ("⚠️" if self.has_anomaly else "🟢")
                    h_name = html_lib.escape(str(h["name"]))
                    h_days = html_lib.escape(str(h["days"]))
                    h_note = html_lib.escape(str(h["note"]))
                    lines.append(
                        f"{icon} <code>{h_name}</code> — Còn: <b>{h_days} ngày</b>\n   └ <i>{h_note}</i>"
                    )
        else:
            short_err = html_lib.escape(str(error_msg).splitlines()[0] if error_msg else "Unknown error")
            lines.append(f"\n⚠️ <b>Chi tiết lỗi:</b> <code>{short_err}</code>")

        return "\n".join(lines)

    def run(self) -> int:
        rc = 0
        self.logger.log(f"=== Khởi chạy No-IP Auto Renew v{VERSION} ===")
        screenshot_to_send = "results.png"

        try:
            self.browser = self.init_browser()
            self.login()
            self.update_hosts()

            should_notify = (
                self.confirmed_count > 0
                or self.has_anomaly
                or self.force_notify
            )

            if should_notify:
                msg = self.build_summary_message(success=True)
                if self.notifier:
                    self.notifier.send_report(msg, photo_path=screenshot_to_send)
            else:
                self.logger.log(
                    "Trạng thái bình thường & chưa đến kỳ Confirm (còn > 7 ngày). "
                    "Bỏ qua gửi Telegram theo cấu hình chỉ báo khi Confirm thành công / có lỗi / quá hạn."
                )
        except Exception as e:
            err_str = str(e)
            self.logger.log(f"LỖI: {err_str}")
            screenshot_to_send = "exception.png"
            if self.browser:
                try:
                    self.browser.save_screenshot(screenshot_to_send)
                except Exception:
                    pass
            # Always notify on error!
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

    username = os.environ.get("NOIP_USERNAME", "").strip()
    password = os.environ.get("NOIP_PASSWORD", "").strip()
    totp_secret = (
        os.environ.get("NOIP_2FA_SECRET_KEY", "").strip()
        or os.environ.get("NOIP_TOTP_SECRET", "").strip()
    )
    debug = int(os.environ.get("NOIP_DEBUG", "1") or "1")
    force_notify = os.environ.get("FORCE_NOTIFY", "false").strip().lower() in ("true", "1", "yes", "y")

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
            "  - NOIP_2FA_SECRET_KEY"
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
        force_notify=force_notify,
    )
    return robot.run()


if __name__ == "__main__":
    sys.exit(main())
