#!/bin/bash
set -uo pipefail  # 启用严格错误处理 / Enable strict error handling

# ---------- 定义变量 / Define variables ----------
APP_NAME="Navicat Premium"
APP_SUPPORT_DIR="$HOME/Library/Application Support/PremiumSoft CyberTech/Navicat CC/Navicat Premium"
PLIST_FILE="$HOME/Library/Preferences/com.navicat.NavicatPremium.plist"
PREFS_DOMAIN="com.navicat.NavicatPremium"
KEYCHAIN_SERVICE="com.navicat.NavicatPremium"

# ---------- 终止 Navicat 进程 / Terminate Navicat process ----------
echo "正在终止 $APP_NAME 进程... / Terminating $APP_NAME process..."
killall "$APP_NAME" 2>/dev/null || true
if pkill -9 -f "Navicat Premium" 2>/dev/null; then
  echo "已成功终止正在运行的 $APP_NAME 进程。/ Successfully terminated running $APP_NAME process."
else
  echo "$APP_NAME 进程未在运行或已由 killall 结束。/ $APP_NAME not running or already quit."
fi

# ---------- 清理应用支持目录的哈希文件 / Cleaning hash files in app support directory ----------
echo "清理应用支持目录的哈希文件... / Cleaning hash files in app support directory..."
if [[ -d "$APP_SUPPORT_DIR" ]]; then
  find "$APP_SUPPORT_DIR" -maxdepth 1 -type f -name '.[0-9A-Fa-f][0-9A-Fa-f]*' 2>/dev/null | \
  while IFS= read -r file; do
    filename=$(basename "$file")
    if echo "$filename" | grep -Eq '^\.([0-9A-Fa-f]{32})$'; then
      echo "删除哈希文件: $filename / Deleting hash file: $filename"
      rm -f "$file"
    fi
  done
else
  echo "应用支持目录不存在，跳过: $APP_SUPPORT_DIR / App support dir missing, skipping."
fi

# ---------- 收集 plist 中 32 位十六进制顶级键 / Collect top-level 32-hex keys ----------
collect_hash_keys_from_plist() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  {
    /usr/libexec/PlistBuddy -c "Print" "$f" 2>/dev/null | grep -Eoa '^\s{4}[0-9A-Fa-f]{32}' | tr -d ' '
    plutil -p "$f" 2>/dev/null | grep -Eo '"[0-9A-Fa-f]{32}"\s*=>' | grep -Eo '[0-9A-Fa-f]{32}'
  } | grep -E '^[0-9A-Fa-f]{32}$' | sort -u
}

# ---------- 处理偏好设置文件 / Handling preferences plist file ----------
echo "处理偏好设置文件... / Processing preferences plist file..."
if [[ -f "$PLIST_FILE" ]]; then
  keys_to_delete=$(collect_hash_keys_from_plist "$PLIST_FILE")
  if [[ -n "$keys_to_delete" ]]; then
    while IFS= read -r key; do
      [[ -z "$key" ]] && continue
      echo "正在删除偏好键: $key / Removing prefs key: $key"
      defaults delete "$PREFS_DOMAIN" "$key" 2>/dev/null || true
      /usr/libexec/PlistBuddy -c "Delete :$key" "$PLIST_FILE" 2>/dev/null || true
    done <<< "$keys_to_delete"
  else
    echo "未找到需要删除的32位哈希密钥。/ No 32-character hash keys found to delete."
  fi
  # 避免 cfprefsd 缓存导致仍读到旧试用状态 / avoid stale prefs cache
  killall cfprefsd 2>/dev/null || true
else
  echo "偏好设置文件不存在: $PLIST_FILE / Preferences plist file not found: $PLIST_FILE"
fi

# ---------- 从 security dump-keychain 文本中提取 Navicat 试用哈希账户 / Parse keychain dump ----------
# 在遇到含服务名的行后，下一条含 "acct" 的行里取 32 位十六进制 blob（与条目顺序一致）
extract_hash_accounts_from_dump_text() {
  local want_acct=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" == *"$KEYCHAIN_SERVICE"* ]]; then
      want_acct=1
      continue
    fi
    if [[ $want_acct -eq 1 && "$line" == *'"acct"'* ]]; then
      if [[ "$line" =~ \"([0-9A-Fa-f]{32})\" ]]; then
        echo "${BASH_REMATCH[1]}"
      fi
      want_acct=0
    fi
  done
}

# ---------- 清理钥匙串中的试用期追踪条目 / Clean trial tracking entries in Keychain ----------
echo "清理钥匙串中的试用期追踪条目... / Cleaning trial tracking entries in Keychain..."
tmp_accounts=$(mktemp "${TMPDIR:-/tmp}/navicat_kc.XXXXXX")
trap 'rm -f "$tmp_accounts"' EXIT

for kc in "$HOME/Library/Keychains/login.keychain-db" "$HOME/Library/Keychains/"*.keychain-db; do
  [[ -r "$kc" ]] || continue
  security dump-keychain "$kc" 2>/dev/null | extract_hash_accounts_from_dump_text >>"$tmp_accounts" || true
done

# 兼容旧版 awk 解析（部分系统上字段顺序不同）/ legacy awk path
for kc in "$HOME/Library/Keychains/login.keychain-db" "$HOME/Library/Keychains/"*.keychain-db; do
  [[ -r "$kc" ]] || continue
  security dump-keychain "$kc" 2>/dev/null | \
    awk '/0x00000007.*'"$KEYCHAIN_SERVICE"'/{found=1} found && /"acct"/{print; found=0}' | \
    sed -E 's/.*<blob>="([^"]*)".*/\1/' >>"$tmp_accounts" || true
done

deleted_count=0
while IFS= read -r account; do
  [[ -z "$account" ]] && continue
  if echo "$account" | grep -Eq '^[0-9A-Fa-f]{32}$'; then
    echo "删除钥匙串条目: $account / Deleting keychain entry: $account"
    if security delete-generic-password -s "$KEYCHAIN_SERVICE" -a "$account" >/dev/null 2>&1; then
      ((deleted_count++)) || true
    fi
  fi
done < <(sort -u "$tmp_accounts" 2>/dev/null)

if [[ $deleted_count -eq 0 ]]; then
  echo "未找到需要删除的钥匙串条目（或已清空）。/ No keychain trial entries removed."
else
  echo "已删除 $deleted_count 个钥匙串条目。/ Deleted $deleted_count keychain entries."
fi

echo "完成。若仍显示过期：请重启 Mac，或按 README 完全卸载后重装。/ Done. Reboot or full uninstall per README if still expired."
