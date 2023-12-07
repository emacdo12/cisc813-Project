import numpy as np
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D

# Assuming optic is a 2D array with dimensions (m, n) where m is the number of machines and n is the number of vulnerabilities
optic = np.array([[0.15,0.12,0.18,0.25,0.38,0.47,0.85,1.55,3.26],[0.14,0.15,0.2,0.26,0.4,0.56,1.45,1.55,3.15],[0.17,0.18,0.18,0.22,0.57,0.64,1.08,1.77,3.68],[0.23,0.21,0.25,0.32,0.39,0.52,0.85,2.2,4.28],[0.28,0.3,0.34,0.48,0.67,0.88,1.53,2.52,4.99]])  
popf = np.array([[0.1,0.11,0.13,0.2,0.25,0.32,0.63,1.03,2.29],[0.11,0.13,0.16,0.21,0.28,0.36,0.59,1.05,2.11],[0.13,0.14,0.14,0.22,0.43,0.36,0.67,1.08,2.29],[0.17,0.2,0.25,0.28,0.35,0.43,0.74,1.18,2.31],[0.25,0.27,0.31,0.36,0.43,0.52,0.85,1.32,2.67]])

# Get the dimensions of the array
num_machines, num_vulnerabilities = optic.shape

# Create 3D meshgrid for x, y, and z
y = np.array([1,2,3,4,5])
x = np.array([10,20,40,60,80,100,150,200,300])
x, y = np.meshgrid(x, y)
z = optic

# Create a 3D plot
fig = plt.figure(figsize=(8, 6))
ax = fig.add_subplot(111, projection='3d')

# Plot the 3D surface
surf = ax.plot_surface(x, y, z, cmap='viridis', edgecolor='k')

# Customize the plot
ax.set_ylabel('Number of Vulnerabilities')
ax.set_xlabel('Number of Machines')
ax.set_zlabel('Time (s)')
ax.set_zlim(0,5)
ax.set_title('Time for Optic Planner vs Number of Machines and Vulnerabilities',wrap=True)

# Add a color bar which maps values to colors
#fig.colorbar(surf, ax=ax, shrink=0.5, aspect=10)

# Show the plot
plt.show()

# Create a 3D plot
fig = plt.figure(figsize=(6, 3))
ax = fig.add_subplot(111, projection='3d')

z = popf

# Plot the 3D surface
surf = ax.plot_surface(x, y, z, cmap='viridis', edgecolor='k')

# Customize the plot
ax.set_ylabel('Number of Vulnerabilities')
ax.set_xlabel('Number of Machines')
ax.set_zlabel('Time (s)')
ax.set_zlim(0,5)
ax.set_title('Time for Popf Planner vs Number of Machines and Vulnerabilities',wrap=True)

# Add a color bar which maps values to colors
#fig.colorbar(surf, ax=ax, shrink=0.5, aspect=10)

# Show the plot
plt.show()

popf_avg = np.array([0.152,0.17,0.198,0.254,0.348,0.398,0.696,1.132,2.334])
optic_avg = np.array([0.194,0.192,0.23,0.306,0.482,0.614,1.152,1.918,3.872]) 

fig = plt.figure(figsize=(4, 3))

ax = fig.add_subplot(111)

print(x[0,:])
print(popf_avg)

ax.plot(x[0,:],popf_avg,label="Popf Planner",marker='o')
ax.plot(x[0,:],optic_avg,label="Optic Planner",marker='s')

ax.set_xlabel('Number of Machines')
ax.set_ylabel('Average Time (s)')
ax.set_title('Comparison between Popf Planner and Optic Planner',wrap=True)
ax.legend()

plt.show()

fig = plt.figure(figsize=(4, 3))
ax = fig.add_subplot(111)

d = np.zeros((10,4))
x = np.array([2,4,6,8])


d[0]= np.array([0,0,0.333333333,0.375])
d[1] = np.array([0.5,0.5,0.333333333,0.375])
d[2] = np.array([0.5,0.5,0.666666667,0.25])
d[3] = np.array([0,0,0.1,0.25])
d[4] = np.array([0,0,0.666666667,0.25])
d[5] = np.array([0,0,0.666666667,0.5])
d[6] = np.array([0.5,0,0.666666667,0.625])
d[7] = np.array([0.5,0.25,0.5,0.375])
d[8] = np.array([0,0.25,0.333333333,0.25])
d[9] = np.array([0.5,0.25,0.166666667,0.125])

d = d * np.array([2,4,6,8])
print(d)
for i in range(d.shape[0]):
    ax.plot(x,d[i],label="d" + str(i))
ax.plot(x,[2,4,6,8],label="Classic")

ax.set_xlabel('Number of Vulnerable Devices')
ax.set_ylim(0,10)
ax.set_ylabel('Percent Compromised Devices')
ax.set_title('Evaluating the number of vulnerable devices being compromised',wrap=True)
ax.legend(ncol = 3)

plt.show()

x = np.array([2,3,4,5,6,7,8])
y = np.array([25.00, 42.86,33.33,40.00,50.00,66.67,50.00])

fig = plt.figure(figsize=(4, 3))
ax = fig.add_subplot(111)
ax.plot(x,y,label="Temporal")
ax.plot(x,[100,100,100,100,100,100,100],label="Classic")


ax.set_xlabel('Number of initially compromised devices')
ax.set_ylim(0,101)
ax.set_ylabel('Percent of other devices compromised')
ax.set_title('Varying initial devices being compromised and its effects',wrap=True)

plt.show()

    
