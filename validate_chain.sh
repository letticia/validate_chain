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

echo "Connecting to ${HOST_PORT} (ServerName: ${SERVERNAME}) ..."

# openssl s_client 実行結果の取得
OUTPUT=$(echo -n | openssl s_client -connect "${HOST_PORT}" -servername "${SERVERNAME}" -showcerts 2>&1)
EXIT_CODE=$?

# 接続エラーチェック
if [ $EXIT_CODE -ne 0 ]; then
    echo "[ERROR] OpenSSL接続に失敗しました。" >&2
    exit 1
fi

# verify error の検知
if echo "$OUTPUT" | grep -q "verify error"; then
    VERIFY_ERR=$(echo "$OUTPUT" | grep -m 1 "verify error")
    ERR_NUM=$(echo "$VERIFY_ERR" | grep -o "num=[0-9]*" | cut -d= -f2)
    ERR_MSG=$(echo "$VERIFY_ERR" | cut -d: -f3-)
    
    echo "[ERROR] 証明書の信頼チェーン検証に失敗しました。（ルートまで辿れません）" >&2
    echo "詳細: ${ERR_MSG} (エラーコード: ${ERR_NUM})" >&2
    echo "原因: サーバー側に中間証明書が正しくインストールされていないか、必要なクロスルート証明書が不足しているため、チェーンが途切れています。" >&2
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

echo "[SUCCESS] Certificate chain is perfectly linked from End-Entity to Root (Total Depth: ${MAX_DEPTH})."
exit 0
