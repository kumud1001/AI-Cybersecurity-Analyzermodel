from sklearn.ensemble import IsolationForest

model=IsolationForest()

X=[
    [50],
    [60],
    [70],
    [400]
]

model.fit(X)

print(model.predict(X))