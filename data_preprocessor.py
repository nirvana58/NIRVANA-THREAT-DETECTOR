import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
import json

class DataPreprocessor:
    def __init__(self):
        self.label_encoders = {}
        self.scaler = StandardScaler()
        self.feature_columns = None
        
    def load_data(self, file_path):
        try:
            if file_path.endswith('.csv'):
                df = pd.read_csv(file_path)
            elif file_path.endswith('.json'):
                df = pd.read_json(file_path)
            else:
                raise ValueError("Unsupported file format. Use CSV or JSON.")
            return df
        except Exception as e:
            raise Exception(f"Error loading data: {str(e)}")
    
    def identify_columns(self, df):
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        categorical_cols = df.select_dtypes(include=['object']).columns.tolist()
        
        # Comprehensive list of label candidates (common naming conventions)
        label_candidates = [
            # Standard ML naming
            'label', 'Label', 'LABEL',
            'class', 'Class', 'CLASS',
            'target', 'Target', 'TARGET',
            'y', 'Y',
            
            # Network security specific
            'attack_type', 'Attack_Type', 'AttackType', 'ATTACK_TYPE',
            'attack_cat', 'Attack_Cat', 'AttackCat',
            'attack', 'Attack', 'ATTACK',
            'threat_type', 'ThreatType', 'Threat_Type',
            'threat', 'Threat', 'THREAT',
            'category', 'Category', 'CATEGORY',
            'classification', 'Classification', 'CLASSIFICATION',
            
            # Intrusion detection specific
            'intrusion', 'Intrusion', 'INTRUSION',
            'anomaly', 'Anomaly', 'ANOMALY',
            'is_attack', 'IsAttack', 'is_Attack',
            'malicious', 'Malicious', 'MALICIOUS',
            
            # Common dataset variations
            'type', 'Type', 'TYPE',
            'status', 'Status', 'STATUS',
            'result', 'Result', 'RESULT',
            'outcome', 'Outcome', 'OUTCOME',
            
            # Specific dataset labels
            'attack_label', 'attack.label',
            'traffic_type', 'TrafficType',
            'conn_state', 'connection_state',
            'activity', 'Activity', 'ACTIVITY',
            
            # Binary labels
            'normal', 'Normal', 'NORMAL',
            'benign', 'Benign', 'BENIGN',
            'is_normal', 'IsNormal',
            
            # Additional patterns with underscores/dashes
            'attack-type', 'attack-category',
            'label_', 'Label_',
            '_label', '_Label'
        ]
        
        label_col = None
        for candidate in label_candidates:
            if candidate in df.columns:
                label_col = candidate
                if candidate in categorical_cols:
                    categorical_cols.remove(candidate)
                if candidate in numeric_cols:
                    numeric_cols.remove(candidate)
                break
        
        # If still not found, try case-insensitive partial matching
        if label_col is None:
            for col in df.columns:
                col_lower = col.lower()
                if any(keyword in col_lower for keyword in ['label', 'class', 'attack', 'threat', 'category', 'type']):
                    # Check if this column has categorical-like data
                    if df[col].dtype == 'object' or df[col].nunique() < 50:
                        label_col = col
                        if col in categorical_cols:
                            categorical_cols.remove(col)
                        if col in numeric_cols:
                            numeric_cols.remove(col)
                        print(f"Auto-detected label column: '{col}'")
                        break
        
        return numeric_cols, categorical_cols, label_col
    
    def handle_missing_values(self, df, numeric_cols, categorical_cols):
        for col in numeric_cols:
            if df[col].isnull().any():
                df[col].fillna(df[col].median(), inplace=True)
        
        for col in categorical_cols:
            if df[col].isnull().any():
                df[col].fillna(df[col].mode()[0], inplace=True)
        
        return df
    
    def encode_categorical(self, df, categorical_cols, fit=True):
        for col in categorical_cols:
            if fit:
                self.label_encoders[col] = LabelEncoder()
                df[col] = self.label_encoders[col].fit_transform(df[col].astype(str))
            else:
                if col in self.label_encoders:
                    le = self.label_encoders[col]
                    df[col] = df[col].astype(str).apply(
                        lambda x: le.transform([x])[0] if x in le.classes_ else -1
                    )
        return df
    
    def normalize_features(self, df, numeric_cols, fit=True):
        if fit:
            df[numeric_cols] = self.scaler.fit_transform(df[numeric_cols])
        else:
            df[numeric_cols] = self.scaler.transform(df[numeric_cols])
        return df
    
    def preprocess_data(self, df, fit=True):
        numeric_cols, categorical_cols, label_col = self.identify_columns(df)
        
        if fit:
            self.feature_columns = numeric_cols + categorical_cols
        
        df = self.handle_missing_values(df, numeric_cols, categorical_cols)
        df = self.encode_categorical(df, categorical_cols, fit=fit)
        df = self.normalize_features(df, numeric_cols, fit=fit)
        
        if label_col and label_col in df.columns:
            X = df[self.feature_columns]
            y = df[label_col]
            return X, y, label_col
        else:
            return df[self.feature_columns], None, None
