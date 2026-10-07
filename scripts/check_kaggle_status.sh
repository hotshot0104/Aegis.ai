#!/usr/bin/env bash
set -e

KERNEL_SLUG="sameersingh0104/aegis-ai-isolation-forest-training"
OUTPUT_DIR="backend/models_saved/kaggle_artifacts"

echo "[*] Checking Kaggle Kernel status for: $KERNEL_SLUG"
/home/sameer/.local/bin/uv run --with kaggle kaggle kernels status "$KERNEL_SLUG"

if [ "$1" == "--pull" ]; then
    echo "[*] Pulling output artifacts from Kaggle to $OUTPUT_DIR..."
    mkdir -p "$OUTPUT_DIR"
    /home/sameer/.local/bin/uv run --with kaggle kaggle kernels output "$KERNEL_SLUG" -p "$OUTPUT_DIR"
    echo "[+] Done. Contents of $OUTPUT_DIR:"
    ls -lh "$OUTPUT_DIR"
fi
