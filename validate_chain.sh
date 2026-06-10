#!/usr/bin/env bash
#
# TLS Certificate Chain Validator (`validate_chain.sh`)
# 
# This software is released under the MIT License.
# See LICENSE file for more details.
#

if [ -z "$1" ]; then
    # 引数なしの場合のデフォルト
    HOST_PORT="certs.nii.ac.jp:443"
    SERVERNAME="certs.nii.ac.jp"
else
    # 引数が1つ以上ある場合
    HOST_PORT="$1"
    
    # 第2引数が省略された場合の自動設定
    if [ -z "$2" ]; then
        # ポート番号（: 以降）を取り除いてサーバー名とする
        SERVERNAME="${1%:*}"
        
        # HOST_PORT にコロン（ポート番号）が含まれていなければ 443 を付与
        if [[ ! "$HOST_PORT" == *:* ]]; then
            HOST_PORT="${HOST_PORT}:443"
        fi
    else
        # 第2引数が明示されている場合
        SERVERNAME="$2"
    fi
fi

# バリデーション（シェルインジェクション対策として簡易的なメタ文字排除）
if [[ "$HOST_PORT" =~ [^a-zA-Z0-9.:-] ]] || [[ "$SERVERNAME" =~ [^a-zA-Z0-9.-] ]]; then
    echo "[ERROR] 無効な文字が引数に含まれています。" >&2
    exit 1
fi

# ホスト名検証オプション（IPv4アドレスの場合は -verify_ip、それ以外は -verify_hostname）
declare -a VERIFY_OPTS
if [[ "$SERVERNAME" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    VERIFY_OPTS=(-verify_ip "$SERVERNAME")
else
    VERIFY_OPTS=(-verify_hostname "$SERVERNAME")
fi

# 古い openssl / LibreSSL ではホスト名検証オプションが無いためスキップ
if ! openssl s_client -help 2>&1 | grep -q -- "-verify_hostname"; then
    echo "[WARN] この openssl はホスト名検証オプションに未対応のため、SAN/CN の一致確認をスキップします。" >&2
    VERIFY_OPTS=()
fi

# 接続タイムアウト（timeout / gtimeout コマンドが利用可能な場合のみ適用）
CONNECT_TIMEOUT=15
declare -a TIMEOUT_CMD
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_CMD=(timeout "$CONNECT_TIMEOUT")
elif command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_CMD=(gtimeout "$CONNECT_TIMEOUT")
fi

echo "Connecting to ${HOST_PORT} (ServerName: ${SERVERNAME}) ..."

# openssl s_client 実行結果の取得
OUTPUT=$(echo -n | "${TIMEOUT_CMD[@]}" openssl s_client -connect "${HOST_PORT}" -servername "${SERVERNAME}" "${VERIFY_OPTS[@]}" -showcerts 2>&1)
EXIT_CODE=$?

# verify error の検知
# 注: ホスト名不一致などでは openssl がハンドシェイクを中断して非ゼロ終了する
# ため、接続エラー判定より先に証明書起因のエラーとして検知する。
if echo "$OUTPUT" | grep -q "verify error"; then
    VERIFY_ERR=$(echo "$OUTPUT" | grep -m 1 "verify error")
    ERR_NUM=$(echo "$VERIFY_ERR" | grep -o "num=[0-9]*" | cut -d= -f2)
    ERR_MSG=$(echo "$VERIFY_ERR" | cut -d: -f3-)
    
    case "$ERR_NUM" in
        62)
            HEADER="証明書のホスト名検証に失敗しました。（SAN/CN の不一致）"
            CAUSE="証明書の SAN/CN が、指定したサーバー名（${SERVERNAME}）と一致していません。証明書の発行対象（コモンネーム / サブジェクト代替名）を確認してください。"
            ;;
        10)
            HEADER="証明書の有効期限検証に失敗しました。（期限切れ）"
            CAUSE="チェーン内の証明書の有効期限が切れています。証明書を更新してください。"
            ;;
        18|19)
            HEADER="証明書の信頼チェーン検証に失敗しました。（信頼されていない証明書）"
            CAUSE="自己署名証明書が使用されているか、チェーンの最上位がこの環境の信頼ストアに登録されていないルート証明書です。"
            ;;
        *)
            HEADER="証明書の信頼チェーン検証に失敗しました。（ルートまで辿れません）"
            CAUSE="サーバー側に中間証明書が正しくインストールされていないか、必要なクロスルート証明書が不足しているため、チェーンが途切れています。"
            ;;
    esac
    echo "[ERROR] ${HEADER}" >&2
    echo "詳細: ${ERR_MSG} (エラーコード: ${ERR_NUM})" >&2
    echo "原因: ${CAUSE}" >&2
    exit 1
fi

# 接続エラーチェック
if [ $EXIT_CODE -ne 0 ]; then
    if [ $EXIT_CODE -eq 124 ]; then
        echo "[ERROR] 接続がタイムアウトしました（${CONNECT_TIMEOUT}秒）。" >&2
    else
        echo "[ERROR] OpenSSL接続に失敗しました。" >&2
    fi
    echo "詳細:" >&2
    echo "$OUTPUT" | tail -n 5 | sed 's/^/  /' >&2
    exit 1
fi

# 検出された最大Depthの取得
MAX_DEPTH=$(echo "$OUTPUT" | grep -Eo "^depth=[0-9]+" | cut -d= -f2 | sort -nr | head -n 1)

if [ -z "$MAX_DEPTH" ]; then
    echo "[ERROR] 証明書の階層情報が取得できませんでした。" >&2
    exit 1
fi

# 解析用の配列
declare -a SUBJECTS
declare -a ISSUERS
declare -a DEPTH_SUBJECTS

# 安全にパースするため、awkでプレーンテキストを出力し、while read でシェル配列に格納（evalインジェクション対策）
while read -r key value; do
    if [[ "$key" == DEPTH_SUBJECTS_* ]]; then
        idx="${key#DEPTH_SUBJECTS_}"
        DEPTH_SUBJECTS[$idx]="$value"
    elif [[ "$key" == SUBJECTS_* ]]; then
        idx="${key#SUBJECTS_}"
        SUBJECTS[$idx]="$value"
    elif [[ "$key" == ISSUERS_* ]]; then
        idx="${key#ISSUERS_}"
        ISSUERS[$idx]="$value"
    fi
done < <(echo "$OUTPUT" | awk '
/^depth=[0-9]+/ {
    match($0, /^depth=[0-9]+/)
    d = substr($0, 7, RLENGTH-6)
    idx = index($0, " ")
    if (idx > 0) {
        subject = substr($0, idx + 1)
        sub(/^[[:space:]]+/, "", subject)
        sub(/[[:space:]]+$/, "", subject)
        printf "DEPTH_SUBJECTS_%s %s\n", d, subject
    }
}
/^[[:space:]]*[0-9]+ s:/ {
    match($0, /[0-9]+/)
    depth = substr($0, RSTART, RLENGTH)
    idx = index($0, "s:")
    subject = substr($0, idx + 2)
    sub(/^[[:space:]]+/, "", subject)
    sub(/[[:space:]]+$/, "", subject)
    printf "SUBJECTS_%s %s\n", depth, subject
    current_depth = depth
}
/^[[:space:]]+i:/ {
    if (current_depth != "") {
        idx = index($0, "i:")
        issuer = substr($0, idx + 2)
        sub(/^[[:space:]]+/, "", issuer)
        sub(/[[:space:]]+$/, "", issuer)
        printf "ISSUERS_%s %s\n", current_depth, issuer
        current_depth = ""
    }
}')

# 各Depthの主体者DN（Subject DN）の表示
# サーバーが送信した証明書（SUBJECTS）に無く、検証パス（DEPTH_SUBJECTS）にのみ
# 存在する場合は、ローカルの証明書ストアで補完されたことを意味する。
# 最上位（ルート証明書）がストア由来なのは正常な構成だが、中間証明書が
# ストア補完されている場合は、サーバーの設定漏れの可能性が高いため警告する。
STORE_FALLBACK=0
echo "Certificate chain:"
for (( d=0; d<=MAX_DEPTH; d++ )); do
    subject="${SUBJECTS[$d]}"
    note=""
    if [ -z "$subject" ]; then
        subject="${DEPTH_SUBJECTS[$d]}"
        if [ -n "$subject" ]; then
            if [ "$d" -eq "$MAX_DEPTH" ]; then
                note=" (ローカル証明書ストアのルート証明書)"
            else
                note=" [WARN] サーバー未送信（ローカル証明書ストアで補完）"
                STORE_FALLBACK=1
            fi
        fi
    fi
    echo "  Depth $d Subject: ${subject:-<NotFound>}${note}"
done

if [ $STORE_FALLBACK -eq 1 ]; then
    echo "[WARN] チェーンの一部がローカルの証明書ストアで補完されています。サーバーが中間証明書を送信していない可能性が高く、この環境では検証に成功しても、初回アクセスのブラウザや他のクライアントでは検証エラーになる恐れがあります。" >&2
fi

# 各証明書の有効期限チェック（サーバーが送信した証明書のみが対象）
EXPIRY_WARN_SECONDS=$((30 * 24 * 3600))
EXPIRY_FAIL=0
cert=""
in_cert=0
cert_idx=0
echo "Certificate expiration:"
while IFS= read -r line; do
    if [[ "$line" == "-----BEGIN CERTIFICATE-----" ]]; then
        in_cert=1
        cert="$line"
    elif [[ "$line" == "-----END CERTIFICATE-----" ]]; then
        cert+=$'\n'"$line"
        in_cert=0
        enddate=$(echo "$cert" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
        if echo "$cert" | openssl x509 -noout -checkend 0 >/dev/null 2>&1; then
            if echo "$cert" | openssl x509 -noout -checkend "$EXPIRY_WARN_SECONDS" >/dev/null 2>&1; then
                echo "  Depth $cert_idx notAfter: ${enddate:-<Unknown>} [OK]"
            else
                echo "  Depth $cert_idx notAfter: ${enddate:-<Unknown>} [WARN] 30日以内に有効期限が切れます。"
            fi
        else
            echo "  Depth $cert_idx notAfter: ${enddate:-<Unknown>} [ERROR] 有効期限切れ" >&2
            EXPIRY_FAIL=1
        fi
        cert_idx=$((cert_idx + 1))
    elif [ $in_cert -eq 1 ]; then
        cert+=$'\n'"$line"
    fi
done <<< "$OUTPUT"

if [ $cert_idx -eq 0 ]; then
    echo "  証明書本体（PEM）を取得できなかったため、有効期限チェックをスキップします。" >&2
fi

# ループによるチェーンの整合性検証
for (( d=0; d<MAX_DEPTH; d++ )); do
    issuer="${ISSUERS[$d]}"
    next_d=$((d + 1))
    
    # Subject は Certificate chain 内の情報を優先し、無ければ depth= 行の情報を使用
    subject="${SUBJECTS[$next_d]}"
    if [ -z "$subject" ]; then
        subject="${DEPTH_SUBJECTS[$next_d]}"
    fi

    # 情報が取得できなかった場合
    if [ -z "$issuer" ] || [ -z "$subject" ]; then
        echo "[ERROR] 証明書の信頼チェーン検証に失敗しました。（Chain broken at Depth $d）" >&2
        echo "詳細: Depth $d と Depth $next_d を繋ぐ証明書情報が見つかりません。" >&2
        echo "  - Depth $d Issuer: ${issuer:-<NotFound>}" >&2
        echo "  - Depth $next_d Subject: ${subject:-<NotFound>}" >&2
        echo "原因: サーバー側に中間証明書が正しくインストールされていないか、必要なクロスルート証明書が不足しているため、チェーンが途切れています。" >&2
        exit 1
    fi

    # i: と s: が完全一致するか確認
    if [ "$issuer" = "$subject" ]; then
        echo "[OK] Depth $d Issuer matches Depth $next_d Subject."
    else
        echo "[ERROR] 証明書の信頼チェーン検証に失敗しました。（Chain broken at Depth $d）" >&2
        echo "詳細: Issuer と Subject の不一致が検出されました。" >&2
        echo "  - Depth $d Issuer: $issuer" >&2
        echo "  - Depth $next_d Subject: $subject" >&2
        echo "原因: サーバー側に中間証明書が正しくインストールされていないか、必要なクロスルート証明書が不足しているため、チェーンが途切れています。" >&2
        exit 1
    fi
done

if [ $EXPIRY_FAIL -eq 1 ]; then
    echo "[ERROR] 有効期限切れの証明書がチェーンに含まれています。証明書を更新してください。" >&2
    exit 1
fi

echo "[SUCCESS] Certificate chain is perfectly linked from End-Entity to Root (Total Depth: ${MAX_DEPTH})."
exit 0
