import subprocess, sys

steps=[
"load_real_data.py",
"real_features.py",
"real_train_model.py"
]

for s in steps:
    print("Running",s)
    subprocess.check_call([sys.executable,s])

print("Pipeline completed")
