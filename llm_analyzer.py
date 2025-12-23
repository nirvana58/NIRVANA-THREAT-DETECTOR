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
