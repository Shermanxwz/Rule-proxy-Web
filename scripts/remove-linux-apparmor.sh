#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "请用 sudo 运行此脚本。" >&2
    exit 1
fi

profile=/etc/apparmor.d/ruleproxy-bwrap
for profile in /etc/apparmor.d/ruleproxy-bwrap /etc/apparmor.d/ruleproxy-bwrap-chromium; do
    if [ -f "$profile" ]; then
        apparmor_parser -R "$profile" 2>/dev/null || true
        rm -f -- "$profile"
    fi
done
rm -f -- /usr/local/lib/ruleproxy-web/bwrap /usr/local/lib/ruleproxy-web/bwrap-chromium
rmdir --ignore-fail-on-non-empty /usr/local/lib/ruleproxy-web 2>/dev/null || true
echo "已移除 RuleProxy 专用 AppArmor 策略和 bubblewrap 副本。"
echo "Ubuntu 原有 AppArmor 与 user namespace 设置未更改。"
