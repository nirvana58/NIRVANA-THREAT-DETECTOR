import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
from data_preprocessor import DataPreprocessor

class ThreatModelTrainer:
    def __init__(self):
        self.model = None
        self.preprocessor = DataPreprocessor()
        self.label_mapping = {}
        
    def train(self, file_path, test_size=0.2, random_state=42):
        print("Loading data...")
        df = self.preprocessor.load_data(file_path)
        
        print(f"Dataset shape: {df.shape}")
        
        print("Preprocessing data...")
        X, y, label_col = self.preprocessor.preprocess_data(df, fit=True)
        
        if y is None:
            raise ValueError("No label column found. Cannot train model.")
        
        if y.dtype == 'object':
            unique_labels = y.unique()
            self.label_mapping = {i: label for i, label in enumerate(unique_labels)}
            y = pd.Series([list(unique_labels).index(val) for val in y])
        
        print("Splitting data...")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
        
        print(f"Training set: {X_train.shape[0]} | Test set: {X_test.shape[0]}")
        
        print("Training Random Forest model...")
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            random_state=random_state,
            n_jobs=-1
        )
        
        self.model.fit(X_train, y_train)
        
        print("\nEvaluating model...")
        y_pred = self.model.predict(X_test)
        
        accuracy = accuracy_score(y_test, y_pred)
        print(f"\nAccuracy: {accuracy:.4f}")
        
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))
        
        return accuracy
    
    def save_model(self):
        joblib.dump(self.model, 'models/threat_classifier.pkl')
        joblib.dump(self.preprocessor, 'models/preprocessor.pkl')
        joblib.dump(self.label_mapping, 'models/label_mapping.pkl')
        print("Model saved to models/")
    
    def load_model(self):
        self.model = joblib.load('models/threat_classifier.pkl')
        self.preprocessor = joblib.load('models/preprocessor.pkl')
        try:
            self.label_mapping = joblib.load('models/label_mapping.pkl')
        except:
            self.label_mapping = {}
