import os
import joblib
import pandas as pd

from lightgbm import LGBMClassifier

from sklearn.model_selection import train_test_split

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

# ============================================================
# PBX LIGHTGBM MULTI-CLASS TRAINING
# ============================================================

DATASET = "data/processed/training_data.json"

MODEL_PATH = "models/lightgbm_pbx_model.pkl"
METADATA_PATH = "models/model_metadata.pkl"

REPORTS_DIR = "reports"

FEATURES = [

    "invite_count_60s",

    "register_count_60s",

    "options_count_60s",

    "failed_count_60s",

    "unique_callers_60s",

    "unique_extensions_60s",

    "unknown_caller_ratio",

    "request_rate",

    "failure_ratio",

    "avg_call_duration",

    "short_call_ratio"

]

LABELS = {

    0: "NORMAL",

    1: "INVITE_FLOOD",

    2: "SIP_SCANNER",

    3: "REGISTER_BRUTE_FORCE",

    4: "EXTENSION_ENUMERATION",

    5: "OPTIONS_FLOOD",

    6: "TOLL_FRAUD"

}


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 80)
    print("           PBX SECURITY LIGHTGBM TRAINING")
    print("=" * 80)

    # --------------------------------------------------------
    # CHECK DATASET
    # --------------------------------------------------------

    if not os.path.exists(DATASET):

        print("\nERROR : Dataset not found")

        print(DATASET)

        return

    # --------------------------------------------------------
    # LOAD DATASET
    # --------------------------------------------------------

    try:

        df = pd.read_json(DATASET)

    except Exception as e:

        print("\nUnable to load dataset")

        print(e)

        return

    print("\nDataset Loaded Successfully")

    print(f"\nTotal Records : {len(df)}")

    print(f"Total Columns : {len(df.columns)}")

    print("\nDataset Columns\n")

    for col in df.columns:

        print("•", col)

    # --------------------------------------------------------
    # VERIFY FEATURES
    # --------------------------------------------------------

    missing = []

    for feature in FEATURES:

        if feature not in df.columns:

            missing.append(feature)

    if len(missing) > 0:

        print("\nMissing Features\n")

        for m in missing:

            print(m)

        return

    if "label" not in df.columns:

        print("\nLabel column not found.")

        return

    # --------------------------------------------------------
    # MISSING VALUES
    # --------------------------------------------------------

    print("\nMissing Values\n")

    print(df.isnull().sum())

    # --------------------------------------------------------
    # CLASS DISTRIBUTION
    # --------------------------------------------------------

    print("\nClass Distribution\n")

    print(df["label"].value_counts())

    print("\nAttack Labels\n")

    for key, value in LABELS.items():

        print(f"{key} -> {value}")

    # --------------------------------------------------------
    # CREATE FEATURES
    # --------------------------------------------------------

    X = df[FEATURES]

    y = df["label"]

    # ============================================================
    # TRAIN / TEST SPLIT
    # ============================================================

    print("\nSplitting Dataset...\n")

    X_train, X_test, y_train, y_test = train_test_split(

        X,

        y,

        test_size=0.30,

        random_state=42,

        stratify=y

    )

    print(f"Training Samples : {len(X_train)}")

    print(f"Testing Samples  : {len(X_test)}")


    # ============================================================
    # CREATE LIGHTGBM MODEL
    # ============================================================

    print("\nCreating LightGBM Model...\n")

    model = LGBMClassifier(

        objective="multiclass",

        num_class=7,

        boosting_type="gbdt",

        learning_rate=0.05,

        n_estimators=300,

        num_leaves=31,

        max_depth=8,

        min_child_samples=5,

        subsample=0.80,

        colsample_bytree=0.80,

        class_weight="balanced",

        random_state=42,

        verbosity=-1

    )


    # ============================================================
    # TRAIN MODEL
    # ============================================================

    print("=" * 80)

    print("Training LightGBM Model...")

    print("=" * 80)

    model.fit(

        X_train,

        y_train

    )

    print("\nTraining Completed Successfully.")

    print("=" * 80)


    # ============================================================
    # MAKE PREDICTIONS
    # ============================================================

    print("\nRunning Predictions...\n")

    predictions = model.predict(X_test)

    probabilities = model.predict_proba(X_test)

    # ============================================================
    # MODEL EVALUATION
    # ============================================================

    print("\n" + "=" * 80)
    print("MODEL PERFORMANCE")
    print("=" * 80)

    accuracy = accuracy_score(

        y_test,

        predictions

    )

    precision = precision_score(

        y_test,

        predictions,

        average="weighted",

        zero_division=0

    )

    recall = recall_score(

        y_test,

        predictions,

        average="weighted",

        zero_division=0

    )

    f1 = f1_score(

        y_test,

        predictions,

        average="weighted",

        zero_division=0

    )

    print(f"\nAccuracy  : {accuracy:.4f} ({accuracy*100:.2f}%)")

    print(f"Precision : {precision:.4f}")

    print(f"Recall    : {recall:.4f}")

    print(f"F1 Score  : {f1:.4f}")


    # ============================================================
    # CONFUSION MATRIX
    # ============================================================

    print("\n" + "=" * 80)
    print("CONFUSION MATRIX")
    print("=" * 80)

    cm = confusion_matrix(

        y_test,

        predictions

    )

    print(cm)

    os.makedirs(REPORTS_DIR, exist_ok=True)

    cm_df = pd.DataFrame(

        cm,

        index=LABELS.values(),

        columns=LABELS.values()

    )

    cm_df.to_csv(

        os.path.join(REPORTS_DIR, "confusion_matrix.csv")

    )


    # ============================================================
    # CLASSIFICATION REPORT
    # ============================================================

    print("\n" + "=" * 80)
    print("CLASSIFICATION REPORT")
    print("=" * 80)

    report = classification_report(

        y_test,

        predictions,

        labels=list(LABELS.keys()),

        target_names=list(LABELS.values()),

        zero_division=0

    )

    print(report)

    # ============================================================
    # FEATURE IMPORTANCE
    # ============================================================

    print("\n" + "=" * 80)
    print("FEATURE IMPORTANCE")
    print("=" * 80)

    importance = pd.DataFrame({

        "Feature": FEATURES,

        "Importance": model.feature_importances_

    })

    importance = importance.sort_values(

        by="Importance",

        ascending=False

    )

    print(importance.to_string(index=False))

    importance.to_csv(

        os.path.join(REPORTS_DIR, "feature_importance.csv"),

        index=False

    )


    # ============================================================
    # TOP 5 IMPORTANT FEATURES
    # ============================================================

    print("\nTop 5 Important Features\n")

    print(

        importance.head(5).to_string(index=False)

    )

    # ============================================================
    # PREDICTION CONFIDENCE
    # ============================================================

    print("\n" + "=" * 80)
    print("SAMPLE PREDICTIONS")
    print("=" * 80)

    results = pd.DataFrame()

    results["Actual Attack"] = pd.Series(y_test.values).map(LABELS)

    results["Predicted Attack"] = pd.Series(predictions).map(LABELS)

    results["Confidence (%)"] = (

        probabilities.max(axis=1) * 100

    ).round(2)

    print(results.head(20).to_string(index=False))

    results.to_csv(

        os.path.join(REPORTS_DIR, "predictions.csv"),

        index=False

    )

    # ============================================================
    # SAVE MODEL
    # ============================================================

    os.makedirs(

        "models",

        exist_ok=True

    )

    joblib.dump(

        {

            "model": model,

            "features": FEATURES,

            "labels": LABELS

        },

        MODEL_PATH

    )

    metadata = {

        "records": len(df),

        "features": FEATURES,

        "classes": LABELS,

        "accuracy": float(accuracy),

        "precision": float(precision),

        "recall": float(recall),

        "f1_score": float(f1)

    }

    joblib.dump(

        metadata,

        METADATA_PATH

    )

    print("\n" + "=" * 80)

    print("MODEL SAVED SUCCESSFULLY")

    print("=" * 80)

    print(f"\nModel Location    : {MODEL_PATH}")
    print(f"Metadata Location : {METADATA_PATH}")
    print(f"Reports Location  : {REPORTS_DIR}/")

# ============================================================
# START PROGRAM
# ============================================================

if __name__ == "__main__":

    main()