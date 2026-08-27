"""
save_models.py
---------------
Trains final RandomForest forecaster + attack-family classifier on ALL
available data (not held out — this is for deployment/demo use, not
evaluation, which already happened in full_train.py) and pickles them
so app.py can load and run inference without retraining every time.
"""

import pandas as pd
import pickle
import json
from sklearn.ensemble import RandomForestClassifier

EXCLUDE_COLS = {
    "day", "window_id", "attack_family", "mitre", "label_attack_now",
    "attack_fraction", "y_forecast", "upcoming_attack_family", "windows_to_attack",
    "kill_chain_stage",
}


def main():
    df = pd.read_csv("full_features.csv")
    feat_cols = [c for c in df.columns if c not in EXCLUDE_COLS]

    forecaster = RandomForestClassifier(
        n_estimators=400, max_depth=10, min_samples_leaf=3,
        class_weight="balanced", random_state=42, n_jobs=-1
    )
    forecaster.fit(df[feat_cols], df["y_forecast"])

    fam_df = df[df.y_forecast == 1]
    family_model = RandomForestClassifier(
        n_estimators=300, max_depth=10, min_samples_leaf=2,
        class_weight="balanced", random_state=42, n_jobs=-1
    )
    family_model.fit(fam_df[feat_cols], fam_df["upcoming_attack_family"])

    with open("rf_forecaster.pkl", "wb") as f:
        pickle.dump({"model": forecaster, "feature_cols": feat_cols}, f)
    with open("rf_family_classifier.pkl", "wb") as f:
        pickle.dump({"model": family_model, "feature_cols": feat_cols}, f)

    print(f"Saved rf_forecaster.pkl ({len(feat_cols)} features)")
    print(f"Saved rf_family_classifier.pkl (classes: {list(family_model.classes_)})")


if __name__ == "__main__":
    main()
