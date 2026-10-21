import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

csv_file_path = "CICIDS2017_sample.csv"
feature_columns = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Length of Fwd Packets",
    "Flow Packets/s",
]


def train_and_save_model():
    print("[Member 4 Task] Loading CICIDS2017 Dataset...")
    df = pd.read_csv(csv_file_path)

    # Clean data
    df = df.dropna()
    df = df.replace([float("inf"), float("-inf")], 0)

    X = df[feature_columns]
    y = df[" Label"].apply(lambda label: 1 if label.strip() == "BENIGN" else -1)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    print(
        f"Dataset Split Complete: {len(X_train)} Training Samples | {len(X_test)} Testing Samples"
    )

    # Train Isolation Forest
    print("Training Isolation Forest on CICIDS2017 features...")
    model = IsolationForest(
        n_estimators=100, contamination=0.10, random_state=42
    )
    model.fit(X_train)

    # Evaluate
    y_pred = model.predict(X_test)
    print("\n--- MODEL EVALUATION REPORT ---")
    print(classification_report(y_test, y_pred, target_names=["Attack", "BENIGN"]))

    # Save trained model to disk
    joblib.dump(model, "netlock_model.pkl")
    print("\nModel successfully saved as 'netlock_model.pkl'!")


if __name__ == "__main__":
    train_and_save_model()