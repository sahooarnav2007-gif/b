#!/bin/zsh
# run_all.sh — end-to-end reproducibility script for the SIH26153 pipeline.
#
# Requires: python3 (>=3.10), dataframe + sklearn + streamlit + scapy installed
#           (see requirements.txt). The CICIDS2017 dataset files must be present
#           under dataset/ with the *.pcap_ISCX.csv naming (gitignored).
#
# Usage:
#   ./run_all.sh data        # raw CICIDS2017 -> full_features.csv (76 features)
#   ./run_all.sh models      # train RF forecaster/family + LSTM world model
#   ./run_all.sh eval        # all evaluations (may take 10-20 min, LSTM heaviest)
#   ./run_all.sh app         # launch the Streamlit demo (CSV or .pcap upload)
#   ./run_all.sh all         # data -> models -> eval
#
# NOTE: dataset CSVs are gitignored; models and results are committed so
#       ./run_all.sh eval + app work without the raw dataset.

set -e
cd "$(dirname "$0")"

export PYTHONUNBUFFERED=1

corpus_done() {
  [ -f full_features.csv ] && echo "  [full_features.csv exists]"
}

case "${1:-all}" in
  data)
    corpus_done
    echo "[1/1] Building full_features.csv from dataset/*.pcap_ISCX.csv ..."
    python3 full_pipeline.py
    echo "DONE -> $PWD/full_features.csv"
    ;;
  models)
    echo "[1/2] Training RandomForest forecaster + family classifier ..."
    python3 full_train.py
    echo "[2/2] Training NumPy-LSTM world model (from scratch, BPTT+Adam) ..."
    python3 lstm_world_model.py
    echo "DONE -> rf_forecaster.pkl, rf_family_classifier.pkl, lstm_weights.json"
    ;;
  eval)
    echo "[1/5] Streaming inference demo run on Friday-DDoS ..."
    python3 infer.py
    echo "[2/5] World-model state-transition dynamics ..."
    python3 world_model_dynamics.py
    echo "[3/5] Forecasting eval (PR curve, lead times) ..."
    python3 eval_forecasting.py
    echo "[4/5] Walk-forward time-series CV (6 folds) ..."
    python3 walk_forward_cv.py
    echo "[5/5] LSTM cross-day improvement experiment (augmented retrain) ..."
    python3 lstm_improve.py
    echo "DONE -> *_summary.json, *_dynamics.json, *_forecasting.json, walk_forward_cv.json"
    ;;
  app)
    echo "Launching Streamlit demo at http://localhost:8501 ..."
    exec streamlit run app.py
    ;;
  all)
    "$0" data && "$0" models && "$0" eval
    ;;
  *)
    echo "Usage: $0 {data|models|eval|app|all}"
    exit 2
    ;;
esac