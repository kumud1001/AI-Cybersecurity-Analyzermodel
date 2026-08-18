from sklearn.ensemble import IsolationForest
import numpy as np

X = np.array([
    [50],
    [60],
    [55],
    [500]
])

model = IsolationForest(random_state=42)
model.fit(X)

prediction = model.predict(X)

print(prediction)