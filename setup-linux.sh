#!/bin/sh
# One-step setup for Linux. Run it as the user who logs in to the desktop, not with sudo:
#   sh setup-linux.sh          install whatever is missing; asks for the sudo password only when needed
#   sh setup-linux.sh --check  change nothing; exit 0 only when RuleProxy is ready to start
# start-linux.sh runs this by itself when something is missing.
set -eu
cd -- "$(dirname -- "$0")"

mode=install
case "${1-}" in
    "") ;;
    --check) mode=check ;;
    --for-start) mode=start ;;
    *) echo "用法：sh setup-linux.sh [--check]" >&2; exit 2 ;;
esac

say() { printf 'RuleProxy: %s\n' "$*"; }
fail() { printf 'RuleProxy: %s\n' "$*" >&2; exit 1; }

restriction=/proc/sys/kernel/apparmor_restrict_unprivileged_userns
dedicated=/usr/local/lib/ruleproxy-web

have() { command -v "$1" >/dev/null 2>&1; }
python_ok() { have python3 && python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>/dev/null; }
# Importing ruleproxy first puts the project's vendor/ folder on the path, as the panel does.
yaml_ok() { have python3 && python3 -c 'import ruleproxy, yaml' >/dev/null 2>&1; }
# Ubuntu 23.10 and later block user namespaces for programs without an AppArmor profile.
apparmor_needed() { [ -r "$restriction" ] && [ "$(cat "$restriction")" = 1 ]; }
apparmor_present() { [ -x "$dedicated/bwrap" ] && [ -x "$dedicated/bwrap-chromium" ]; }
apparmor_current() {
    apparmor_present \
        && cmp -s /usr/bin/bwrap "$dedicated/bwrap" \
        && cmp -s /usr/bin/bwrap "$dedicated/bwrap-chromium" \
        && cmp -s apparmor/ruleproxy-bwrap /etc/apparmor.d/ruleproxy-bwrap \
        && cmp -s apparmor/ruleproxy-bwrap-chromium /etc/apparmor.d/ruleproxy-bwrap-chromium
}
runtime_ok() { python3 install_runtime.py --check; }

if [ "$mode" = check ]; then
    if [ "$(id -u)" -ne 0 ] && python_ok && yaml_ok && have bwrap && have xdg-dbus-proxy && have dbus-send && runtime_ok \
        && { ! apparmor_needed || apparmor_present; }; then
        exit 0
    fi
    exit 1
fi

[ "$(id -u)" -ne 0 ] || fail "请用登录桌面的普通用户运行，不要用 sudo 或 root。需要管理员权限的步骤会自动请求 sudo 密码。"
case "$(uname -m)" in
    x86_64 | amd64) ;;
    *) fail "目前只提供 x86-64（amd64）版本，这台电脑是 $(uname -m)。" ;;
esac

packages=""
have python3 || packages="python3"
have bwrap || packages="$packages bubblewrap"
have xdg-dbus-proxy || packages="$packages xdg-dbus-proxy"
have dbus-send || packages="$packages dbus"
if have apt-get; then
    yaml_ok || packages="$packages python3-yaml"
    packages=${packages# }
    if [ -n "$packages" ]; then
        have sudo || fail "需要 sudo 来安装 $packages。请用管理员账户安装后重新运行。"
        say "安装系统软件包：$packages（需要 sudo 密码）"
        sudo apt-get update || say "部分软件源更新失败，仍继续安装。"
        # shellcheck disable=SC2086  # one word per package
        sudo apt-get install -y --no-install-recommends $packages || fail "无法安装 $packages，请查看上面的错误后重新运行。"
    fi
elif [ -n "${packages# }" ]; then
    fail "请先用系统的软件管理器安装 bubblewrap、xdg-dbus-proxy、dbus-send 和 Python 3.10 以上，再重新运行。例如 Fedora：sudo dnf install bubblewrap xdg-dbus-proxy dbus-tools python3-pyyaml；Arch：sudo pacman -S bubblewrap xdg-dbus-proxy dbus python-yaml"
fi

python_ok || fail "需要 Python 3.10 或更高版本（Ubuntu 22.04 及以后自带）。当前：$(python3 --version 2>&1)"
if ! yaml_ok; then
    # python3 is not the interpreter the system package serves (pyenv, conda…): install PyYAML into vendor/.
    if python3 -m pip --version >/dev/null 2>&1; then
        say "为 $(command -v python3) 安装 PyYAML 到本项目的 vendor 目录…"
        python3 -m pip install --quiet --disable-pip-version-check --target vendor -r requirements.txt || true
    fi
    yaml_ok || fail "找不到 PyYAML。请为 $(command -v python3) 安装 PyYAML 后重新运行。"
fi

if apparmor_needed && ! apparmor_current; then
    have sudo || fail "需要 sudo 来加载 AppArmor 策略。请用管理员账户运行：sudo sh scripts/setup-linux-apparmor.sh"
    say "加载 RuleProxy 专用的 AppArmor 策略（需要 sudo 密码）…"
    sudo sh scripts/setup-linux-apparmor.sh
fi

python3 install_runtime.py --if-needed

python3 - <<'EOF'
import sys
from ruleproxy.linux_runtime import probe

result = probe()
if not result["supported"]:
    sys.exit("RuleProxy: 隔离检查未通过：" + result["detail"])
print("RuleProxy: 隔离检查通过。" + result["detail"])
EOF

if [ "$mode" = install ]; then
    say "已准备好。打开面板：sh start-linux.sh"
else
    say "已准备好，正在打开面板…"
fi
