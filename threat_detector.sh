#!/bin/bash

# AI Network Threat Detector - Terminal Edition
# Complete automation script for network threat detection

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
print_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                                                              ║"
    echo "║        🛡️  AI NETWORK THREAT DETECTOR - TERMINAL TOOL       ║"
    echo "║                                                              ║"
    echo "║              Machine Learning + LLM Analysis                 ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Log function
log() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Setup function - first time only
setup() {
    print_banner
    log "Starting initial setup..."
    
    # Check Python
    if ! command_exists python3; then
        error "Python 3 is not installed. Please install Python 3.9 or higher."
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
    log "Found Python $PYTHON_VERSION"
    
    # Create project structure
    log "Creating project directories..."
    mkdir -p models data/training data/samples logs
    
    # Check if venv exists
    if [ ! -d "venv" ]; then
        log "Creating virtual environment..."
        python3 -m venv venv
    fi
    
    # Activate venv
    source venv/bin/activate
    
    # Upgrade pip
    log "Upgrading pip..."
    pip install --upgrade pip --quiet
    
    # Install requirements
    log "Installing Python packages..."
    pip install pandas numpy scikit-learn joblib ollama plotly --quiet
    
    # Check Ollama
    if ! command_exists ollama; then
        warning "Ollama is not installed!"
        echo ""
        echo "Please install Ollama:"
        echo "  curl https://ollama.ai/install.sh | sh"
        echo ""
        read -p "Do you want to continue without Ollama? (y/n): " continue_without_ollama
        if [ "$continue_without_ollama" != "y" ]; then
            exit 1
        fi
    else
        log "Ollama is installed"
        
        # Check if model exists
        if ! ollama list | grep -q "llama3.2:1b"; then
            info "Pulling llama3.2:1b model..."
            ollama pull llama3.2:1b
        else
            log "Model llama3.2:1b already available"
        fi
    fi
    
    # Create Python files if they don't exist
    create_python_files
    
    log "Setup complete! hurray"
    sleep 2
}

# Create all Python files inline
create_python_files() {
    log "Creating Python modules..."
    
    # data_preprocessor.py
    if [ ! -f "data_preprocessor.py" ]; then
        cat > data_preprocessor.py << 'PYEOF'
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
PYEOF
    fi
    
    # train_model.py
    if [ ! -f "train_model.py" ]; then
        cat > train_model.py << 'PYEOF'
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
PYEOF
    fi
    
    # llm_analyzer.py
    if [ ! -f "llm_analyzer.py" ]; then
        cat > llm_analyzer.py << 'PYEOF'
import ollama

class LLMThreatAnalyzer:
    def __init__(self, model_name='llama3.2:1b'):
        self.model_name = model_name
    
    def format_network_data(self, row_data, feature_names):
        formatted = "Network Traffic Data:\n"
        for feature, value in zip(feature_names, row_data):
            formatted += f"  - {feature}: {value}\n"
        return formatted
    
    def analyze_threat(self, network_data, ml_prediction, confidence, label_mapping=None):
        threat_label = ml_prediction
        if label_mapping and ml_prediction in label_mapping:
            threat_label = label_mapping[ml_prediction]
        
        prompt = f"""You are a network security expert analyzing potential threats.

{network_data}

Machine Learning Model Results:
- Prediction: {threat_label}
- Confidence: {confidence:.2%}

Provide a concise analysis (max 200 words):
1. THREAT ASSESSMENT: Is this malicious? (Yes/No/Uncertain)
2. THREAT TYPE: What type of attack?
3. EXPLANATION: Why is this a threat?
4. RECOMMENDED ACTION: What should be done?
5. RISK LEVEL: (Low/Medium/High/Critical)"""

        try:
            response = ollama.chat(
                model=self.model_name,
                messages=[
                    {'role': 'system', 'content': 'You are a cybersecurity analyst. Be concise.'},
                    {'role': 'user', 'content': prompt}
                ]
            )
            return response['message']['content']
        except Exception as e:
            return f"LLM analysis unavailable: {str(e)}"
PYEOF
    fi
    
    # generate_sample_data.py
    if [ ! -f "generate_sample_data.py" ]; then
        cat > generate_sample_data.py << 'PYEOF'
import pandas as pd
import numpy as np
import random

def generate_ip():
    return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def generate_normal_traffic(n=1000):
    data = []
    protocols = ['TCP', 'UDP', 'ICMP']
    ports = [80, 443, 53, 22, 21, 25]
    
    for _ in range(n):
        data.append({
            'src_ip': generate_ip(),
            'dst_ip': generate_ip(),
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice(ports),
            'protocol': random.choice(protocols),
            'packet_size': random.randint(64, 1500),
            'duration': round(random.uniform(0.001, 5.0), 3),
            'packets_sent': random.randint(1, 100),
            'packets_received': random.randint(1, 100),
            'bytes_sent': random.randint(100, 10000),
            'bytes_received': random.randint(100, 10000),
            'syn_flag': random.choice([0, 1]),
            'ack_flag': random.choice([0, 1]),
            'fin_flag': random.choice([0, 1]),
            'rst_flag': 0,
            'label': 'normal'
        })
    return data

def generate_port_scan(n=200):
    data = []
    attacker = generate_ip()
    target = generate_ip()
    
    for _ in range(n):
        data.append({
            'src_ip': attacker,
            'dst_ip': target,
            'src_port': random.randint(40000, 50000),
            'dst_port': random.randint(1, 65535),
            'protocol': 'TCP',
            'packet_size': 60,
            'duration': 0.001,
            'packets_sent': 1,
            'packets_received': 0,
            'bytes_sent': 60,
            'bytes_received': 0,
            'syn_flag': 1,
            'ack_flag': 0,
            'fin_flag': 0,
            'rst_flag': random.choice([0, 1]),
            'label': 'port_scan'
        })
    return data

def generate_ddos(n=300):
    data = []
    target = generate_ip()
    
    for _ in range(n):
        data.append({
            'src_ip': generate_ip(),
            'dst_ip': target,
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice([80, 443]),
            'protocol': 'TCP',
            'packet_size': random.randint(500, 1500),
            'duration': round(random.uniform(0.001, 0.1), 3),
            'packets_sent': random.randint(100, 1000),
            'packets_received': 0,
            'bytes_sent': random.randint(50000, 500000),
            'bytes_received': 0,
            'syn_flag': 1,
            'ack_flag': 0,
            'fin_flag': 0,
            'rst_flag': 0,
            'label': 'ddos'
        })
    return data

def main():
    all_data = []
    all_data.extend(generate_normal_traffic(1000))
    all_data.extend(generate_port_scan(200))
    all_data.extend(generate_ddos(300))
    
    df = pd.DataFrame(all_data)
    df = df.sample(frac=1).reset_index(drop=True)
    
    df.to_csv('data/samples/sample_network_traffic.csv', index=False)
    test_df = df.sample(n=100).reset_index(drop=True)
    test_df.to_csv('data/samples/test_traffic.csv', index=False)
    
    print(f"Generated {len(df)} records")
    print(f"Saved to data/samples/sample_network_traffic.csv")
    print(f"Test file: data/samples/test_traffic.csv")
    print("\nDistribution:")
    print(df['label'].value_counts())

if __name__ == "__main__":
    main()
PYEOF
    fi
}

# Generate sample data
generate_sample_data() {
    print_banner
    log "Generating sample network data..."
    
    source venv/bin/activate
    python3 generate_sample_data.py
    
    log "Sample data generated successfully!"
    sleep 2
}

# Train model
train_model() {
    print_banner
    
    # List available datasets
    echo -e "${CYAN}Available Training Datasets:${NC}"
    echo ""
    
    training_files=()
    if [ -d "data/training" ] && [ "$(ls -A data/training 2>/dev/null)" ]; then
        echo "Training directory:"
        for file in data/training/*; do
            if [ -f "$file" ]; then
                training_files+=("$file")
                echo "  [$((${#training_files[@]}))] $(basename "$file")"
            fi
        done
    fi
    
    sample_files=()
    if [ -d "data/samples" ] && [ "$(ls -A data/samples 2>/dev/null)" ]; then
        echo ""
        echo "Sample directory:"
        for file in data/samples/*; do
            if [ -f "$file" ]; then
                sample_files+=("$file")
                echo "  [$((${#training_files[@]} + ${#sample_files[@]}))] $(basename "$file")"
            fi
        done
    fi
    
    all_files=("${training_files[@]}" "${sample_files[@]}")
    
    if [ ${#all_files[@]} -eq 0 ]; then
        warning "No training data found!"
        echo ""
        read -p "Generate sample data? (y/n): " gen_sample
        if [ "$gen_sample" = "y" ]; then
            generate_sample_data
            train_model
            return
        else
            error "Cannot train without data"
            return
        fi
    fi
    
    echo ""
    echo -e "${YELLOW}[0]${NC} Enter custom path"
    echo -e "${YELLOW}[b]${NC} Back to main menu"
    echo ""
    read -p "Select dataset number: " dataset_choice
    
    if [ "$dataset_choice" = "b" ]; then
        return
    elif [ "$dataset_choice" = "0" ]; then
        read -p "Enter path to training data: " training_file
    elif [ "$dataset_choice" -ge 1 ] && [ "$dataset_choice" -le ${#all_files[@]} ]; then
        training_file="${all_files[$((dataset_choice-1))]}"
    else
        error "Invalid selection"
        sleep 2
        train_model
        return
    fi
    
    if [ ! -f "$training_file" ]; then
        error "File not found: $training_file"
        sleep 2
        return
    fi
    
    log "Training model with: $training_file"
    echo ""
    
    source venv/bin/activate
    
    cat > train_now.py << 'PYEOF'
import sys
from train_model import ThreatModelTrainer

trainer = ThreatModelTrainer()
accuracy = trainer.train(sys.argv[1])
trainer.save_model()
print(f"\n✅ Training complete! Accuracy: {accuracy:.2%}")
PYEOF
    
    python3 train_now.py "$training_file"
    rm train_now.py
    
    echo ""
    log "Model saved to models/"
    echo ""
    read -p "Press Enter to continue..."
}

# Analyze network data
analyze_data() {
    print_banner
    
    # Check if model exists
    if [ ! -f "models/threat_classifier.pkl" ]; then
        error "No trained model found!"
        echo ""
        info "You need to train a model first."
        echo ""
        read -p "Train a model now? (y/n): " train_now
        if [ "$train_now" = "y" ]; then
            train_model
            if [ ! -f "models/threat_classifier.pkl" ]; then
                return
            fi
        else
            return
        fi
    fi
    
    # List available data files
    echo -e "${CYAN}Available Data Files to Analyze:${NC}"
    echo ""
    
    analyze_files=()
    
    if [ -d "data/samples" ] && [ "$(ls -A data/samples 2>/dev/null)" ]; then
        echo "Sample data:"
        for file in data/samples/*; do
            if [ -f "$file" ]; then
                analyze_files+=("$file")
                echo "  [$((${#analyze_files[@]}))] $(basename "$file")"
            fi
        done
    fi
    
    if [ -d "data/training" ] && [ "$(ls -A data/training 2>/dev/null)" ]; then
        echo ""
        echo "Training data:"
        for file in data/training/*; do
            if [ -f "$file" ]; then
                analyze_files+=("$file")
                echo "  [$((${#analyze_files[@]}))] $(basename "$file")"
            fi
        done
    fi
    
    echo ""
    echo -e "${YELLOW}[0]${NC} Enter custom path"
    echo -e "${YELLOW}[b]${NC} Back to main menu"
    echo ""
    read -p "Select file to analyze: " file_choice
    
    if [ "$file_choice" = "b" ]; then
        return
    elif [ "$file_choice" = "0" ]; then
        read -p "Enter path to data file: " analyze_file
    elif [ "$file_choice" -ge 1 ] && [ "$file_choice" -le ${#analyze_files[@]} ]; then
        analyze_file="${analyze_files[$((file_choice-1))]}"
    else
        error "Invalid selection"
        sleep 2
        analyze_data
        return
    fi
    
    if [ ! -f "$analyze_file" ]; then
        error "File not found: $analyze_file"
        sleep 2
        return
    fi
    
    # Configuration
    echo ""
    echo -e "${CYAN}Analysis Configuration:${NC}"
    echo ""
    read -p "Use LLM for detailed analysis? (y/n) [y]: " use_llm
    use_llm=${use_llm:-y}
    
    if [ "$use_llm" = "y" ]; then
        echo ""
        echo "Select LLM model:"
        echo "  [1] llama3.2:1b (fastest)"
        echo "  [2] phi3:mini (balanced)"
        echo "  [3] gemma:2b (accurate)"
        read -p "Choice [1]: " llm_choice
        llm_choice=${llm_choice:-1}
        
        case $llm_choice in
            1) llm_model="llama3.2:1b";;
            2) llm_model="phi3:mini";;
            3) llm_model="gemma:2b";;
            *) llm_model="llama3.2:1b";;
        esac
        
        read -p "Max threats to analyze with LLM [5]: " max_analyze
        max_analyze=${max_analyze:-5}
        
        read -p "Confidence threshold (0.0-1.0) [0.7]: " threshold
        threshold=${threshold:-0.7}
    fi
    
    log "Analyzing: $analyze_file"
    echo ""
    
    source venv/bin/activate
    
    # Create analysis script
    cat > analyze_now.py << PYEOF
import sys
import pandas as pd
import numpy as np
import joblib
from data_preprocessor import DataPreprocessor
from llm_analyzer import LLMThreatAnalyzer

# Load model
model = joblib.load('models/threat_classifier.pkl')
preprocessor = joblib.load('models/preprocessor.pkl')
try:
    label_mapping = joblib.load('models/label_mapping.pkl')
except:
    label_mapping = {}

# Load data
print("Loading data...")
if sys.argv[1].endswith('.csv'):
    data = pd.read_csv(sys.argv[1])
else:
    data = pd.read_json(sys.argv[1])

print(f"Loaded {len(data)} records")

# Preprocess
print("Preprocessing...")
X, _, _ = preprocessor.preprocess_data(data.copy(), fit=False)

# Predict
print("Running ML classification...")
predictions = model.predict(X)
probabilities = model.predict_proba(X)
confidences = np.max(probabilities, axis=1)

# Results
results = pd.DataFrame({
    'Record': range(len(data)),
    'Prediction': [label_mapping.get(p, f"Class {p}") for p in predictions],
    'Confidence': confidences
})

print("\n" + "="*70)
print("ANALYSIS RESULTS")
print("="*70)
print(f"\nTotal Records: {len(results)}")
print(f"Threats Detected: {len(results[results['Prediction'] != 'normal'])}")
print(f"Average Confidence: {results['Confidence'].mean():.2%}")

print("\nThreat Distribution:")
print(results['Prediction'].value_counts())

print("\nTop 10 High-Confidence Predictions:")
print(results.nlargest(10, 'Confidence')[['Record', 'Prediction', 'Confidence']].to_string(index=False))

# LLM Analysis
use_llm = sys.argv[2] == 'y'
if use_llm:
    llm_model = sys.argv[3]
    max_analyze = int(sys.argv[4])
    threshold = float(sys.argv[5])
    
    print("\n" + "="*70)
    print("DETAILED LLM ANALYSIS")
    print("="*70)
    
    analyzer = LLMThreatAnalyzer(model_name=llm_model)
    
    high_conf = results[results['Confidence'] >= threshold].nlargest(max_analyze, 'Confidence')
    
    for idx, row in high_conf.iterrows():
        print(f"\n{'─'*70}")
        print(f"Record #{row['Record']} - {row['Prediction']} ({row['Confidence']:.2%})")
        print(f"{'─'*70}")
        
        network_data = analyzer.format_network_data(
            X.iloc[idx].values,
            preprocessor.feature_columns
        )
        
        analysis = analyzer.analyze_threat(
            network_data,
            predictions[idx],
            confidences[idx],
            label_mapping
        )
        
        print(analysis)

# Save results
output_file = sys.argv[1].replace('.csv', '_results.csv').replace('.json', '_results.csv')
results.to_csv(output_file, index=False)
print(f"\n✅ Results saved to: {output_file}")
PYEOF
    
    if [ "$use_llm" = "y" ]; then
        python3 analyze_now.py "$analyze_file" "y" "$llm_model" "$max_analyze" "$threshold"
    else
        python3 analyze_now.py "$analyze_file" "n" "" "" ""
    fi
    
    rm analyze_now.py
    
    echo ""
    read -p "Press Enter to continue..."
}

# Main menu
main_menu() {
    while true; do
        print_banner
        
        echo -e "${CYAN}Main Menu:${NC}"
        echo ""
        echo "  [1] 🎯 Generate Sample Data"
        echo "  [2] 🧠 Train Model"
        echo "  [3] 🔍 Analyze Network Data"
        echo "  [4] ℹ️  System Information"
        echo "  [5] 🚪 Exit"
        echo ""
        
        read -p "Select option: " choice
        
        case $choice in
            1) generate_sample_data ;;
            2) train_model ;;
            3) analyze_data ;;
            4) show_info ;;
            5) 
                echo ""
                log "Thank you for using AI Network Threat Detector!"
                exit 0
                ;;
            *)
                error "Invalid option"
                sleep 1
                ;;
        esac
    done
}

# Show system info
show_info() {
    print_banner
    
    echo -e "${CYAN}System Information:${NC}"
    echo ""
    
    echo "Python Version: $(python3 --version 2>&1)"
    
    if command_exists ollama; then
        echo "Ollama: Installed"
        echo "Available Models:"
        ollama list | grep -v "NAME"
    else
        echo "Ollama: Not installed"
    fi
    
    echo ""
    echo "Project Structure:"
    echo "  models/: $(ls models/ 2>/dev/null | wc -l) files"
    echo "  data/training/: $(ls data/training/ 2>/dev/null | wc -l) files"
    echo "  data/samples/: $(ls data/samples/ 2>/dev/null | wc -l) files"
    
    if [ -f "models/threat_classifier.pkl" ]; then
        echo ""
        echo "✅ Trained model: Available"
    else
        echo ""
        echo "❌ Trained model: Not found"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# Main execution
main() {
    # Check if first run
    if [ ! -d "venv" ] || [ ! -f "data_preprocessor.py" ]; then
        setup
    else
        # Just activate venv
        source venv/bin/activate 2>/dev/null
    fi
    
    # Start main menu
    main_menu
}

# Run
main