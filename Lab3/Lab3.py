import streamlit as st
import numpy as np
import matplotlib.pyplot as plt

st.set_page_config(page_title="Virus Simulation Tool", layout="centered")
st.title("Virus Simulation — Educational & Safe")

st.markdown(
    "Safe simulation showing virus spread, patching (defense), and detection/quarantine, with network visualization."
)

# -------------------------
# Sidebar parameters
# -------------------------
st.sidebar.header("Simulation Settings")
num_nodes = st.sidebar.slider("Number of computers", 10, 100, 30, step=5)
initial_infected = st.sidebar.slider("Initially infected", 1, 10, 2)
infection_prob = st.sidebar.slider("Infection probability per contact", 0.0, 1.0, 0.3, step=0.05)
patch_prob = st.sidebar.slider("Chance of patching per step", 0.0, 1.0, 0.1, step=0.05)
detection_prob = st.sidebar.slider("Detection chance per infected per step", 0.0, 1.0, 0.2, step=0.05)
contacts_per_step = st.sidebar.slider("Contacts per infected per step", 1, 10, 3)
num_steps = st.sidebar.slider("Number of steps", 5, 50, 25)
avg_degree = st.sidebar.slider("Average connections per computer", 1, 10, 3)

# -------------------------
# Build a random network
# -------------------------
adj = np.zeros((num_nodes, num_nodes), dtype=bool)
for i in range(num_nodes):
    connections = np.random.choice(
        [x for x in range(num_nodes) if x != i],
        size=min(avg_degree, num_nodes-1),
        replace=False
    )
    adj[i, connections] = True
adj = np.triu(adj) + np.triu(adj).T  # make symmetric

# -------------------------
# Initialize states
# -------------------------
SUS, INF, PATCH, QUAR = 0, 1, 2, 3
states = np.zeros(num_nodes, dtype=int)
infected_indices = np.random.choice(num_nodes, size=initial_infected, replace=False)
states[infected_indices] = INF

history = []

# -------------------------
# Simulation loop
# -------------------------
for step in range(num_steps):
    new_states = states.copy()
    for i, state in enumerate(states):
        if state == INF:
            # infect neighbors
            neighbors = np.where(adj[i])[0]
            if len(neighbors) > 0:
                contacts = np.random.choice(neighbors, size=min(contacts_per_step, len(neighbors)), replace=False)
                for c in contacts:
                    if new_states[c] == SUS and np.random.rand() < infection_prob:
                        new_states[c] = INF
            # detection
            if np.random.rand() < detection_prob:
                new_states[i] = QUAR
        elif state == SUS:
            # patching
            if np.random.rand() < patch_prob:
                new_states[i] = PATCH
    states = new_states
    history.append(states.copy())

# -------------------------
# Prepare data for time-series plot
# -------------------------
history = np.array(history)
sus_counts = np.sum(history == SUS, axis=1)
inf_counts = np.sum(history == INF, axis=1)
patch_counts = np.sum(history == PATCH, axis=1)
quar_counts = np.sum(history == QUAR, axis=1)

# -------------------------
# Line plot: dynamics over time
# -------------------------
st.subheader("Virus Spread Over Time")
fig1, ax1 = plt.subplots(figsize=(8,4))
ax1.plot(range(1, num_steps+1), sus_counts, label="Susceptible", marker='o')
ax1.plot(range(1, num_steps+1), inf_counts, label="Infected", marker='o')
ax1.plot(range(1, num_steps+1), patch_counts, label="Patched", marker='o')
ax1.plot(range(1, num_steps+1), quar_counts, label="Quarantined", marker='o')
ax1.set_xlabel("Step")
ax1.set_ylabel("Number of computers")
ax1.set_title("Virus Spread Simulation Over Time")
ax1.grid(True)
ax1.legend()
st.pyplot(fig1)

# -------------------------
# Network visualization: final state
# -------------------------
st.subheader("Final Network State")
angles = np.linspace(0, 2*np.pi, num_nodes, endpoint=False)
xpos = np.cos(angles)
ypos = np.sin(angles)

colors_map = {SUS: "#1f77b4", INF: "#d62728", PATCH: "#2ca02c", QUAR: "#9467bd"}
labels_map = {SUS: "Susceptible", INF: "Infected", PATCH: "Patched", QUAR: "Quarantined"}

fig2, ax2 = plt.subplots(figsize=(6,6))

# Draw edges
for i in range(num_nodes):
    for j in range(i+1, num_nodes):
        if adj[i,j]:
            ax2.plot([xpos[i], xpos[j]], [ypos[i], ypos[j]], color='gray', alpha=0.3, linewidth=0.5)

# Draw nodes
for state_val in [SUS, INF, PATCH, QUAR]:
    idxs = np.where(states == state_val)[0]
    if len(idxs) > 0:
        ax2.scatter(xpos[idxs], ypos[idxs], s=100, color=colors_map[state_val], edgecolors='k', label=labels_map[state_val])

ax2.set_xticks([])
ax2.set_yticks([])
ax2.set_aspect('equal')
ax2.set_title("Computers in Network by State")
ax2.legend(loc='upper right')
st.pyplot(fig2)

# -------------------------
# Explanation
# -------------------------
st.markdown("""
**Explanation:**
- **Susceptible**: Computers that can still get infected.
- **Infected**: Currently infected computers.
- **Patched**: Computers that received patches and are immune.
- **Quarantined**: Infected computers detected and isolated.
- **Line plot** shows dynamics over time.
- **Network plot** shows final network state and which computers are infected, patched, or quarantined.
""")
