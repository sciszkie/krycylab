from sklearn.tree import DecisionTreeClassifier, plot_tree
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from nfstream import NFStreamer
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix
import seaborn as sns
import numpy as np

class ML:
    def __init__(self,normal_stream, mal_stream)-> None:
        self.normal_stream=normal_stream
        self.malicious_stream=mal_stream
        self.accuracy=None
        self.conf_matrix=None
        self.tree_model = None
        self.train_and_evaluate_decision_tree()

    def prepare_data(self, normal_stream, malicious_stream):
        normal_flows = normal_stream.to_pandas()
        normal_flows['label'] = 0 
        malicious_flows = malicious_stream.to_pandas()
        malicious_flows['label'] = 1 
        data = pd.concat([normal_flows, malicious_flows], ignore_index=True)
        data=data.select_dtypes(include=[np.number])
        X = data.drop('label', axis=1)
        y = data['label']
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
        return (X_train, X_test, y_train, y_test)
    
    
    def train_and_evaluate_decision_tree(self, max_depth=3, criterion='gini'):
        X_train, X_test, y_train, y_test = self.prepare_data(self.normal_stream, self.malicious_stream)
        self.tree_model = DecisionTreeClassifier(max_depth=max_depth, criterion=criterion, random_state=42)
        self.tree_model.fit(X_train, y_train)

        predictions = self.tree_model.predict(X_test)

        # Obliczenie metryk
        self.accuracy = accuracy_score(y_test, predictions)
        self.conf_matrix = confusion_matrix(y_test, predictions)

        # Wizualizacja drzewa
        plt.figure(figsize=(20,10))
        plot_tree(self.tree_model, filled=True, feature_names=X_train.columns, class_names=['Normal', 'Malicious'], fontsize=10)
        plt.title("Wizualizacja drzewa decyzyjnego")
        plt.savefig('decision_tree.png')
        plt.clf()
        sns.heatmap(self.conf_matrix,annot=True,fmt="d")
        plt.title("Macierz błędów")
        plt.savefig('confusion_matrix.png')