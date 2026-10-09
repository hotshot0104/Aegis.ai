#!/usr/bin/env bash
set -e

KERNEL_SLUG="sameersingh0104/raksha-ai-cicids2017-large-eval"
OUTPUT_DIR="backend/models_saved/kaggle_artifacts"

echo "[*] Checking CIC-IDS2017 Large-Scale Evaluation status on Kaggle:"
/home/sameer/.local/bin/uv run --with kaggle kaggle kernels status "$KERNEL_SLUG"

if [ "$1" == "--pull" ]; then
    echo "[*] Pulling output artifacts from Kaggle to $OUTPUT_DIR..."
    mkdir -p "$OUTPUT_DIR"
    /home/sameer/.local/bin/uv run --with kaggle kaggle kernels output "$KERNEL_SLUG" -p "$OUTPUT_DIR"
    echo "[+] Done. Contents of $OUTPUT_DIR:"
    ls -lh "$OUTPUT_DIR"
fi
