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
    --global) mode=global ;;
    *) echo "用法：sh setup-linux.sh [--check|--global]" >&2; exit 2 ;;
esac

say() { printf 'RuleProxy: %s\n' "$*"; }
fail() { printf 'RuleProxy: %s\n' "$*" >&2; exit 1; }

restriction=/proc/sys/kernel/apparmor_restrict_unprivileged_userns
dedicated=/usr/local/lib/ruleproxy-web

have() { command -v "$1" >/dev/null 2>&1; }
python_ok() { have python3 && python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>/dev/null; }
# Importing ruleproxy first puts the project's vendor/ folder on the path, as the panel does.
yaml_ok() { have python3 && python3 -c 'import ruleproxy, yaml' >/dev/null 2>&1; }
# The protected helper deliberately uses the OS interpreter, even when the
# desktop panel uses conda/pyenv. Its parser must be available independently.
system_yaml_ok() { /usr/bin/python3 -I -c 'import yaml' >/dev/null 2>&1; }
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
if [ "$mode" = global ]; then
    have nft || packages="$packages nftables"
    have ip || packages="$packages iproute2"
    have pkexec || packages="$packages pkexec"
fi
if have apt-get; then
    if ! yaml_ok || { [ "$mode" = global ] && ! system_yaml_ok; }; then
        packages="$packages python3-yaml"
    fi
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
if [ "$mode" = global ]; then
    /usr/bin/python3 -I -c 'import sys; sys.exit(sys.version_info < (3, 10))' >/dev/null 2>&1 \
        || fail "受保护的全局组件需要 /usr/bin/python3 为 3.10 或更高版本；普通面板仍使用当前 Python。"
fi
if ! yaml_ok; then
    # python3 is not the interpreter the system package serves (pyenv, conda…): install PyYAML into vendor/.
    if python3 -m pip --version >/dev/null 2>&1; then
        say "为 $(command -v python3) 安装 PyYAML 到本项目的 vendor 目录…"
        python3 -m pip install --quiet --disable-pip-version-check --target vendor -r requirements.txt || true
    fi
    yaml_ok || fail "找不到 PyYAML。请为 $(command -v python3) 安装 PyYAML 后重新运行。"
fi

if [ "$mode" = global ] && ! system_yaml_ok; then
    # Non-apt/venv setup: copy only pure parser source as the desktop user;
    # the privileged installer subsequently copies it into its protected tree.
    python3 - <<'GLOBAL_VENDOR_YAML'
from pathlib import Path
import shutil
import tempfile
import ruleproxy
import yaml

source = Path(yaml.__file__).resolve().parent
vendor = Path.cwd() / 'vendor'
target = vendor / 'yaml'
if vendor.is_symlink() or target.is_symlink():
    raise SystemExit('RuleProxy: vendor/yaml 不能是符号链接。')
if source != target.resolve():
    if target.exists():
        raise SystemExit('RuleProxy: vendor/yaml 不完整，请先检查该项目依赖目录后重试。')
    vendor.mkdir(parents=True, exist_ok=True, mode=0o755)
    staged = Path(tempfile.mkdtemp(prefix='.yaml-global-', dir=vendor))
    try:
        for item in source.iterdir():
            if item.suffix == '.py':
                if item.is_symlink() or not item.is_file():
                    raise SystemExit('RuleProxy: 当前 PyYAML 源文件无效。')
                shutil.copyfile(item, staged / item.name)
        if not (staged / '__init__.py').is_file():
            raise SystemExit('RuleProxy: 当前 PyYAML 源文件不完整。')
        staged.chmod(0o755)
        staged.rename(target)
    finally:
        if staged.exists():
            shutil.rmtree(staged)
print('RuleProxy: 已为受保护的全局组件准备纯 Python PyYAML。')
GLOBAL_VENDOR_YAML
fi

if apparmor_needed && ! apparmor_current; then
    have sudo || fail "需要 sudo 来加载 AppArmor 策略。请用管理员账户运行：sudo sh scripts/setup-linux-apparmor.sh"
    say "加载 RuleProxy 专用的 AppArmor 策略（需要 sudo 密码）…"
    sudo sh scripts/setup-linux-apparmor.sh
fi

python3 install_runtime.py --if-needed

if [ "$mode" = global ]; then
    have sudo || fail "安装受保护的全局组件需要 sudo；面板仍以普通用户运行。"
    say "安装固定的 Linux 全局组件（需要 sudo 密码；不会启动接管）…"
    sudo /usr/bin/python3 -I "$PWD/scripts/install-linux-global.py" --source "$PWD" --owner "$(id -u)"
    say "全局组件已安装；在网页中选择全局模式后手动启动。"
    exit 0
fi

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
