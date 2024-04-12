# %%
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import io
import sys

# Check if an argument was provided
if len(sys.argv) > 1:
    example = sys.argv[1]
else:
    example = input("Please enter the example you ran:")
# %%
timing = pd.read_csv('~/sp1/examples/'+example+'/script/output.csv')
timing['Chip'] = timing['Chip'].astype('category')
timing['Phase'] = timing['Phase'].astype('category')
timing['Process'] = timing['Process'].astype('category')
print(timing['Phase'].unique())

# %% [markdown]
# # Trace Timing

# %%
trace_timing = timing[(timing['Process']=='Trace Generation')]

# %%
trace = trace_timing[['Chip', 'CPU Time', 'Phase']].groupby(['Chip','Phase'], observed=False).sum().reset_index()

# %%
total_time_1 = trace['CPU Time'].sum()
print(f"Total time to generate traces: {total_time_1}")

# %%
phase_1_bars = sns.barplot(x='CPU Time', y ='Chip', data=trace[trace['Phase']=='Phase 1'], color='darkblue', orient = 'h', label = 'Phase 1 Trace')
phase_2_bars = sns.barplot(x='CPU Time', y='Chip', data = trace[trace['Phase']=='Phase 2'], color='lightblue', orient = 'h', left = trace[trace['Phase']=='Phase 1']['CPU Time'], label = 'Phase 2 Trace')
plt.legend(loc='center left', bbox_to_anchor=(1, 0.5))
#plt.xscale('log')
plt.title('Phase 1 and Phase 2 Trace Generation Times for '+example)
plt.savefig('/Users/eugenerabinovich/white_paper/trace_times_'+example+'.png', bbox_inches='tight')
# plt.show()

# %% [markdown]
# # LDE Timing

# %%
lde_timing = timing[(timing['Process']=='LDE Generation')][['Chip', 'CPU Time', 'Phase']].groupby(['Chip','Phase'], observed=False).sum().reset_index()

# %%
total_time_lde_1 = lde_timing['CPU Time'].sum()
print(f"Total time for LDE: {total_time_lde_1}")

# %%
plt.clf()
phase_1_lde_bars = sns.barplot(x='CPU Time', y = 'Chip', data=lde_timing[lde_timing['Phase']=='Phase 1'], color='darkblue', orient = 'h', label = 'Phase 1 LDE')
phase_2_lde_bars = sns.barplot(x='CPU Time', y='Chip', data = lde_timing[lde_timing['Phase']=='Phase 2'], color='lightblue', orient = 'h', left = lde_timing[lde_timing['Phase']=='Phase 1']['CPU Time'], label = 'Phase 2 LDE')
plt.legend(loc='center left', bbox_to_anchor=(1, 0.5))
#plt.xscale('log')
plt.title('Phase 1 and Phase 2 LDE Generation Times for '+example)
plt.savefig('/Users/eugenerabinovich/white_paper/lde_gen_times_'+example+'.png', bbox_inches='tight')
#plt.show()

# %%
perm_timing = timing[(timing['Process']=='Permutation Trace Generation')][['Chip', 'CPU Time', 'Phase']].groupby(['Chip','Phase'], observed=False).sum().reset_index()

# %%
total_time_perm_1 = perm_timing['CPU Time'].sum()
print(f"Total time for Permutation Trace: {total_time_perm_1}")

# %%
plt.clf()
phase_2_perm_bars = sns.barplot(x='CPU Time', y='Chip', data = perm_timing[perm_timing['Phase']=='Phase 2'], orient = 'h')
#plt.xscale('log')
plt.title('Permutation Trace Times for '+example)
plt.savefig('/Users/eugenerabinovich/white_paper/perm_gen_times_'+example+'.png', bbox_inches='tight')
#plt.show()

# %%
quot_timing = timing[(timing['Process']=='Quotient')][['Chip', 'CPU Time', 'Phase']].groupby(['Chip','Phase'], observed=True).sum().reset_index()

# %%
total_time_quot = quot_timing['CPU Time'].sum()
print(f"Total time for Quotient Trace: {total_time_quot}")

# %%
plt.clf()
phase_2_quot_bars = sns.barplot(x='CPU Time', y='Chip', data = quot_timing[quot_timing['Phase']=='Phase 2'], orient = 'h')
#plt.xscale('log')
plt.title('Quotient Times for '+example)
plt.savefig('/Users/eugenerabinovich/white_paper/quot_gen_times_'+example+'.png', bbox_inches='tight')
#plt.show()

# %%
agg_timing = timing[['CPU Time', 'Process']].groupby(['Process'], observed=True).sum().reset_index()


print(agg_timing['Process'].unique())
print(timing['Process'].unique())  
# %%
plt.clf()
phase_2_agg_pie = plt.pie(agg_timing['CPU Time'], labels = agg_timing['Process'], autopct='%1.1f%%')
#plt.xscale('log')
plt.title('Process Times for '+example)
plt.savefig('/Users/eugenerabinovich/white_paper/process_times_'+example+'.png', bbox_inches='tight')
#plt.show()

# %% [markdown]
# # Time For All Merkle and Total Time

# %%
print(timing[timing['Chip']=='All'][['Phase', 'Process', 'CPU Time']].groupby(['Phase', 'Process'], observed = True).sum())


column_counts = pd.read_csv("column_counts.csv")

agg_col_ct = column_counts.groupby('Chip').max()
plt.clf()
bar1 = sns.barplot(x='Trace Width', y = 'Chip', data=agg_col_ct, color='darkblue', orient = 'h', label = 'Main')
bar2 = sns.barplot(x='Permutation Width', y='Chip', data = agg_col_ct, color='lightblue', orient = 'h', left = column_counts.groupby('Chip', observed = False).max()['Trace Width'], label = 'Permutation')
plt.legend(loc='center left', bbox_to_anchor=(1, 0.5))
plt.savefig('/Users/eugenerabinovich/white_paper/'+example+'_column_counts.png', bbox_inches='tight')
plt.title('Main and Permutation Column Counts by Chip')


plt.clf()
msk = timing['Process']=='Quotient'
for elem in {'Permutation Trace Generation', 'LDE Generation', 'Trace Generation'}:
    msk = msk |(timing['Process']==elem)
grp_by_chip = timing[msk][['Process', 'Chip', 'CPU Time']].groupby(['Process', 'Chip'], observed = True).sum().reset_index()
sns.barplot(data = grp_by_chip, y = 'Chip', x='CPU Time', hue = 'Process', hue_order=grp_by_chip['Process'].unique(), order = grp_by_chip['Chip'].unique())
plt.title('Chip and Process Breakdown for '+example)
plt.savefig('/Users/eugenerabinovich/white_paper/'+example+'_chip_process.png')



# %%
