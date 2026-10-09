import pandas as pd
df_all = pd.DataFrame({'Label': ['BENIGN', 'BENIGN'], 'day_file': ['Monday-WorkingHours', 'Tuesday']})
df_train_benign = df_all[(df_all['Label'] == 'BENIGN') & (df_all['day_file'].str.contains('Monday', case=False))]
print("Matched rows:", len(df_train_benign))
