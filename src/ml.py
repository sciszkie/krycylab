from sklearn.tree import DecisionTreeClassifier, plot_tree
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from nfstream import NFStreamer
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix
import seaborn as sns
import numpy as np
from joblib import dump, load
import matplotlib

matplotlib.use('TkAgg')

class ML:
    def __init__(self,normal_stream, mal_stream)-> None:
        self.normal_stream=normal_stream
        self.malicious_stream=mal_stream
        self.accuracy=None
        self.conf_matrix=None
        self.tree_model = None
        self.feature_columns = [
            'bidirectional_duration_ms', 'bidirectional_packets', 'src2dst_bytes', 
            'dst2src_bytes', 'src2dst_mean_ps', 'dst2src_mean_ps', 
            'bidirectional_max_ps', 'bidirectional_stddev_ps', 
            'bidirectional_syn_packets', 'application_is_guessed'
        ]

    def get_flow_data_for_ml(self, flow):
        return {
            'bidirectional_duration_ms': flow.bidirectional_duration_ms,
            'bidirectional_packets': flow.bidirectional_packets,
            'src2dst_bytes': flow.src2dst_bytes,
            'dst2src_bytes': flow.dst2src_bytes,
            'src2dst_mean_ps': flow.src2dst_mean_ps,
            'dst2src_mean_ps': flow.dst2src_mean_ps,
            'bidirectional_max_ps': flow.bidirectional_max_ps,
            'bidirectional_stddev_ps': flow.bidirectional_stddev_ps,
            'bidirectional_syn_packets': flow.bidirectional_syn_packets,
            'application_is_guessed': flow.application_is_guessed
        }
    def generate_data (self, normal_stream, mal_stream):
        normal_flows = normal_stream.to_pandas()
        normal_flows['label'] = 0 
        malicious_flows = mal_stream.to_pandas()
        malicious_flows['label'] = 1 
        data = pd.concat([normal_flows, malicious_flows], ignore_index=True)
        data=data.select_dtypes(include=[np.number])
        data = data[self.feature_columns + ['label']]
        return data
    
    def prepare_data(self):
        data=self.generate_data(self.normal_stream,self.malicious_stream)
        X = data.drop('label', axis=1)
        y = data['label']
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
        return (X_train, X_test, y_train, y_test)    
    
    def train_and_evaluate_decision_tree(self):
        X_train, X_test, y_train, y_test = self.prepare_data()
        self.tree_model = DecisionTreeClassifier(max_depth=3, criterion='gini', random_state=42)
        self.tree_model.fit(X_train, y_train)
    
        predictions = self.tree_model.predict(X_test)
        self.accuracy = accuracy_score(y_test, predictions)
        self.conf_matrix = confusion_matrix(y_test, predictions)

        dump(self.tree_model, 'decision_tree_model.joblib')

        plt.figure(figsize=(20,10))
        plot_tree(self.tree_model, filled=True, feature_names=X_train.columns, class_names=['Normal', 'Malicious'], fontsize=10)
        plt.title("Wizualizacja drzewa decyzyjnego")
        plt.savefig('report/decision_tree.png')
        plt.show()
        plt.clf()
        sns.heatmap(self.conf_matrix, annot=True, fmt="d")
        plt.title("Macierz błędów")
        plt.savefig('report/confusion_matrix.png')
        plt.show()


    def ml_find_suspicious_flow(self,flow):
        model = load('decision_tree_model.joblib')
        
        flow_df = pd.DataFrame([self.get_flow_data_for_ml(flow)])
        
        flow_df = flow_df[self.feature_columns]

        prediction = model.predict(flow_df)
        if prediction == 1:
            return True
        else:
            return False


    def test_model_on_new_data(self, new_normal_stream, new_malicious_stream):
        data=self.generate_data(new_normal_stream,new_malicious_stream)
        
        X_new = data.drop('label', axis=1)
        y_new = data['label']

        model = load('decision_tree_model.joblib')
        predictions = model.predict(X_new)
        accuracy = accuracy_score(y_new, predictions)
        print(f"Procent poprawnie sklasyfikowanych danych przez model: {accuracy * 100:.2f}%")
        conf_matrix= confusion_matrix(y_new, predictions)
        sns.heatmap(conf_matrix, annot=True, fmt="d")
        plt.title("Macierz błędów")
        plt.show()

    def prepare_data_for_retrain(self, new_normal_stream, new_malicious_stream):
        
        new_normal_flows = new_normal_stream.to_pandas()
        new_normal_flows['label'] = 0 
        new_malicious_flows = new_malicious_stream.to_pandas()
        new_malicious_flows['label'] = 1  
        
        old_normal_flows = self.normal_stream.to_pandas()
        old_normal_flows['label'] = 0
        old_malicious_flows = self.malicious_stream.to_pandas()
        old_malicious_flows['label'] = 1
        

        combined_normal_flows = pd.concat([old_normal_flows, new_normal_flows], ignore_index=True)
        combined_malicious_flows = pd.concat([old_malicious_flows, new_malicious_flows], ignore_index=True)

        combined_data = pd.concat([combined_normal_flows, combined_malicious_flows], ignore_index=True)
        combined_data = combined_data.select_dtypes(include=[np.number])
        combined_data = combined_data[self.feature_columns + ['label']]
        
        X = combined_data.drop('label', axis=1)
        y = combined_data['label']
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
        return (X_train, X_test, y_train, y_test)
    
    def retrain_model(self, new_normal_stream, new_malicious_stream):

        X_train, X_test, y_train, y_test = self.prepare_data_for_retrain(new_normal_stream,new_malicious_stream)
        self.tree_model = DecisionTreeClassifier(max_depth=3, criterion='gini', random_state=42)
        self.tree_model.fit(X_train, y_train)
    
        predictions = self.tree_model.predict(X_test)
        self.accuracy = accuracy_score(y_test, predictions)
        self.conf_matrix = confusion_matrix(y_test, predictions)

        dump(self.tree_model, 'decision_tree_model.joblib')

        plt.figure(figsize=(20,10))
        plot_tree(self.tree_model, filled=True, feature_names=X_train.columns, class_names=['Normal', 'Malicious'], fontsize=10)
        plt.title("Wizualizacja nowego drzewa decyzyjnego")
        plt.savefig('report/decision_tree.png')
        plt.show()
        plt.clf()
        sns.heatmap(self.conf_matrix, annot=True, fmt="d")
        plt.title("Macierz błędów")
        plt.savefig('report/confusion_matrix.png')
        plt.show()
