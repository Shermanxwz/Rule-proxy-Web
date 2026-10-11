#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "请用 sudo 运行此脚本；面板和应用仍应以普通用户启动。" >&2
    exit 1
fi

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
source_bwrap=/usr/bin/bwrap
target_dir=/usr/local/lib/ruleproxy-web
target_bwrap=$target_dir/bwrap
target_chromium_bwrap=$target_dir/bwrap-chromium
profile=/etc/apparmor.d/ruleproxy-bwrap
chromium_profile=/etc/apparmor.d/ruleproxy-bwrap-chromium

if [ ! -x "$source_bwrap" ] || [ -L "$source_bwrap" ]; then
    echo "找不到 Ubuntu 软件包提供的 /usr/bin/bwrap。" >&2
    exit 1
fi
if [ "$(stat -c '%u:%g' "$source_bwrap")" != "0:0" ]; then
    echo "/usr/bin/bwrap 必须由 root 所有。" >&2
    exit 1
fi
if ! command -v apparmor_parser >/dev/null 2>&1; then
    echo "找不到 apparmor_parser。请先安装 Ubuntu 的 AppArmor 用户空间工具。" >&2
    exit 1
fi
if [ ! -r "$root/apparmor/ruleproxy-bwrap" ] || [ ! -r "$root/apparmor/ruleproxy-bwrap-chromium" ]; then
    echo "找不到项目提供的 AppArmor 策略文件。" >&2
    exit 1
fi

install -d -o root -g root -m 0755 "$target_dir"
install -o root -g root -m 0755 "$source_bwrap" "$target_bwrap"
install -o root -g root -m 0755 "$source_bwrap" "$target_chromium_bwrap"
install -o root -g root -m 0644 "$root/apparmor/ruleproxy-bwrap" "$profile"
install -o root -g root -m 0644 "$root/apparmor/ruleproxy-bwrap-chromium" "$chromium_profile"

if ! apparmor_parser -r "$profile" || ! apparmor_parser -r "$chromium_profile"; then
    echo "AppArmor 未加载策略。已保留 fail-closed；请检查 $profile。" >&2
    exit 1
fi

echo "已为 RuleProxy 的专用 bubblewrap 路径加载 AppArmor 策略。"
echo "全机 user namespace 限制未更改；请以普通用户重新打开 RuleProxy 面板。"
