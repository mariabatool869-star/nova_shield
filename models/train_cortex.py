import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import pickle

# 1. Load the 10,000-row dataset
print("Loading dataset...")
df = pd.read_csv("models/nova_dataset.csv")

X = df.drop("label", axis=1)
y = df["label"]

# 2. Split into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 3. Train the model
print("Training CORTEX on 8,000 records...")
model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
model.fit(X_train, y_train)

# 4. Evaluate the model
print("\n--- Model Evaluation on 2,000 Hidden Records ---")
predictions = model.predict(X_test)
print(classification_report(y_test, predictions))

# 5. Save the trained brain
with open("models/cortex_model.pkl", "wb") as f:
    pickle.dump(model, f)

print("✅ CORTEX brain retrained and saved to models/cortex_model.pkl")