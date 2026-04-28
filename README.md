# useful_scripts

This is a place to share useful scripts for ARC systems.

Scripts are located at ```/apps/common/useful_scripts``` 

The module file is located at ```/apps/common/modules/all/useful_scripts.lua``` to prepend ```/apps/common/useful_scripts``` to $PATH and is loaded by default.

> These useful scripts will help if you want to pick into what going in your job and on the cluster.
 
#### Most useful scripts (commands)

| Use | Command | What it does |
| --- | --- | --- |
| Check job efficiency | `showjobusage <jobid>` | Shows CPU, memory, and GPU usage for your job. |
| Check GPU usage | `showuserjobgpu` | Shows GPU usage for your running GPU jobs. |
| Check node status | `nodestat` | Shows which nodes are free, busy, or unavailable. |
| Check a specific node | `shownodeusage <node>` | Shows CPU, memory, and GPU usage on one node. |
| Check quota and balances | `quota` | Shows your quotas and allocation balances. |
| Start an interactive job | `interact -A <account>` | Starts an interactive Slurm session with cluster-aware defaults. |


#### More useful scripts

- `showjobprocessesusage` - per-process CPU, memory, and GPU stats inside a job.
- `getjobutilurl` - prints a dashboard (grafana) link for your job, visualize your resource utilization.
- `jobload` - quick load summary for the nodes in a running job.
- `gpumon` - logs GPU stats.

#### Cluster and node status

- `loginusage` - shows your load and processes on login nodes.

#### Allocation and accounting

- `showusage` - shows account usage history and limits.
- `getusage` - shows service unit usage by account, PI, or user.
- `showqos` - shows QoS limits.

#### Software and licensing

- `lmstat` - checks license server status.

