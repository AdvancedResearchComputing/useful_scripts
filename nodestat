#!/usr/bin/env python3
import subprocess
import argparse
import math
import re 

def parse_tres(tres_str):
    tres = {}
    #cpu, mem, gres/gpu
    for item in tres_str.split(","):
        key, val = item.split("=")
        tres[key] = val.strip()
    if 'cpu' not in tres:
        tres['cpu'] = '0'
    if 'mem' not in tres:
        tres['mem'] = '0G'
    if 'gres/gpu' not in tres:
        tres['gres/gpu'] = '0'
    return tres

def get_slurm_node_info():
    node_info = {}
    command = "scontrol show node"
    result = subprocess.run(command.split(), stdout=subprocess.PIPE, universal_newlines=True)

    for line in result.stdout.split('\n'):
        line = line.strip()
        if line.startswith('NodeName'):
            node_name = line.split('=')[1].split(' ')[0]
            node_info[node_name] = {}
        elif line.startswith('Partitions'):
            partition_name = line.split('=')[1]
            node_info[node_name]['partition'] = partition_name
        #CfgTRES
        elif line.startswith('CfgTRES'):
            line = line.replace('CfgTRES=', '')
            cfg_tres = parse_tres(line)
            node_info[node_name]['cfg_tres'] = cfg_tres
        #AllocTRES
        elif line.startswith('AllocTRES'):
            line = line.replace('AllocTRES=', '')
            if line == '':
                alloc_tres = {'cpu': '0', 'mem': '0G', 'gres/gpu': '0'}
            else:
                alloc_tres = parse_tres(line)
            node_info[node_name]['alloc_tres'] = alloc_tres
        #status
        elif line.startswith('State'):
            state = line.split('=')[1].split(' ')[0].strip()
            node_info[node_name]['state'] = state
    
    return node_info

def parse_mem(mem_str):
    if mem_str.endswith("M"):
        mem = float(mem_str[:-1]) / 1000
    elif mem_str.endswith("K"):
        mem = float(mem_str[:-1]) / 1000 / 1000
    else:
        mem = float(mem_str[:-1])
    return int(mem)

def count_cpus_from_ids(cpu_ids_str):
    """Count number of CPUs from CPU_IDs string like '0-10,71-107' or '0-47'"""
    if not cpu_ids_str:
        return 0
    total = 0
    for part in cpu_ids_str.split(','):
        if '-' in part:
            start, end = part.split('-')
            total += int(end) - int(start) + 1
        else:
            total += 1
    return total


def get_slurm_jobs():
    result = subprocess.run(["scontrol", "show", "job", "-d"], stdout=subprocess.PIPE, universal_newlines=True)
    job_str = result.stdout.split('\n\n')
    job_info = {}
    for job in job_str:
        job = job.strip()
        if len(job.split('JobId=')) == 1:
            continue
        job_id = job.split('JobId=')[1].split(' ')[0]
        job_info[job_id] = {}
        job_info[job_id]['nodes'] = job.split(' NodeList=')[1].split(' ')[0].strip().split(',')
        job_info[job_id]['state'] = job.split('JobState=')[1].split(' ')[0]
        job_info[job_id]['user'] = job.split('UserId=')[1].split(' ')[0].split('(')[0]
        #TRES
        if len(job.split('AllocTRES=')) > 0:
            tres_str = job.split('AllocTRES=')[1].split(' ')[0]
        else:
            tres_str = job.split('TRES=')[1].split(' ')[0]
        if 'null'in tres_str:
            tres_str = 'cpu=0,mem=0G,gres/gpu=0'
        tres = parse_tres(tres_str)
        job_info[job_id]['tres'] = tres

        # Parse per-node allocations from detailed output
        # Look for lines like: Nodes=tc031 CPU_IDs=0-10,71-107 Mem=93312 GRES=
        job_info[job_id]['node_alloc'] = {}  # node_name -> {cpus, mem, gpus, gpu_idx}
        job_info[job_id]['gpu_idx'] = {}

        for line in job.split('\n'):
            line = line.strip()
            if line.startswith('Nodes=') and 'CPU_IDs=' in line:
                # Parse the per-node allocation line
                # Format: Nodes=NAME CPU_IDs=X-Y Mem=N GRES=...
                node_match = re.search(r'Nodes=(\S+)', line)
                cpu_match = re.search(r'CPU_IDs=([^\s]+)', line)
                mem_match = re.search(r'Mem=(\d+)', line)
                gres_match = re.search(r'GRES=(\S*)', line)

                if node_match and cpu_match:
                    node_spec = node_match.group(1)
                    cpu_ids = cpu_match.group(1)
                    mem_mb = int(mem_match.group(1)) if mem_match else 0
                    gres = gres_match.group(1) if gres_match else ''

                    # Count CPUs from CPU_IDs
                    cpu_count = count_cpus_from_ids(cpu_ids)

                    # Parse GPUs from GRES
                    gpu_count = 0
                    gpu_idx = ''
                    if gres and 'gpu:' in gres:
                        gpu_type_count = re.search(r'gpu:\w+:(\d+)', gres)
                        if gpu_type_count:
                            gpu_count = int(gpu_type_count.group(1))
                        # Check for IDX
                        idx_match = re.search(r'IDX:([^)]+)', gres)
                        if idx_match:
                            gpu_idx = idx_match.group(1)

                    # Expand node names (handle ranges like tc[031,037-038])
                    expanded_nodes = expand_node_name(node_spec)
                    for node in expanded_nodes:
                        job_info[job_id]['node_alloc'][node] = {
                            'cpus': cpu_count,
                            'mem': mem_mb,
                            'gpus': gpu_count,
                            'gpu_idx': gpu_idx
                        }
                        if gpu_idx:
                            job_info[job_id]['gpu_idx'][node] = gpu_idx

    return job_info

def expand_node_name(node_spec):
    nodes = []
    match = re.match(r'^(\w+(-\w+)?)\[(.*)\]$', node_spec)
    if match:
        prefix = match.group(1)
        ranges = match.group(3).split(',')
        for r in ranges:
            if '-' in r:
                start, end = r.split('-')
                width = len(start)
                for i in range(int(start), int(end) + 1):
                    nodes.append(f"{prefix}{i:0{width}d}")
            else:
                nodes.append(f"{prefix}{r}")
    else:
        # Single node name without brackets
        nodes.append(node_spec)
    return nodes


def parse_slurm_conf_nodes():
    node_specs = {}
    defaults = {}
    
    with open("/etc/slurm/slurm.conf", "r") as f:
        for line in f:
            line = line.strip()
            if not line.startswith("NodeName="):
                continue
            
            # Parse NodeName line
            # Format: NodeName=NAME [Specs...]
            parts = line.split()
            node_part = parts[0]
            node_spec = node_part.split("=")[1]
            
            # Parse specs into dict
            specs = {}
            for part in parts[1:]:
                if "=" in part:
                    key, val = part.split("=", 1)
                    specs[key] = val
            
            if node_spec == "DEFAULT":
                # Store defaults
                if 'Sockets' in specs:
                    defaults['Sockets'] = int(specs['Sockets'])
                if 'CoresPerSocket' in specs:
                    defaults['CoresPerSocket'] = int(specs['CoresPerSocket'])
                if 'ThreadsPerCore' in specs:
                    defaults['ThreadsPerCore'] = int(specs['ThreadsPerCore'])
                if 'RealMemory' in specs:
                    defaults['RealMemory'] = int(specs['RealMemory'])
                if 'Gres' in specs:
                    defaults['Gres'] = specs['Gres']
            else:
                # Apply defaults then override with specific specs
                node_defaults = defaults.copy()
                node_defaults.update(specs)
                
                # Calculate total CPUs
                sockets = int(node_defaults.get('Sockets', 1))
                cores = int(node_defaults.get('CoresPerSocket', 1))
                threads = int(node_defaults.get('ThreadsPerCore', 1))
                cpus = sockets * cores * threads
                
                # Get memory
                real_mem = node_defaults.get('RealMemory', '0')
                memory = int(real_mem) if real_mem else 0
                
                # Parse GPUs from Gres
                gpus = 0
                if 'Gres' in node_defaults:
                    gres = node_defaults['Gres']
                    # Match pattern like gpu:a100:8 or gpu:h200:8
                    gpu_match = re.search(r'gpu:\w+:(\d+)', gres)
                    if gpu_match:
                        gpus = int(gpu_match.group(1))
                
                # Expand node names and store specs for each
                expanded_nodes = expand_node_name(node_spec)
                for node in expanded_nodes:
                    node_specs[node] = {
                        'cpus': cpus,
                        'memory': memory,
                        'gpus': gpus,
                        'sockets': sockets,
                        'cores_per_socket': cores
                    }
    
    return node_specs

def get_nodes_in_reservation(reservation):
    command = f"scontrol show res {reservation}"
    result = subprocess.run(command.split(), stdout=subprocess.PIPE, universal_newlines=True)
    nodes_line = [line for line in result.stdout.split('\n') if line.strip().startswith('Nodes=')]

    if nodes_line:
        nodes_str = nodes_line[0].split('=')[1].strip()
        nodes = []
        
        if '[' in nodes_str:
            base_name = nodes_str.split('[')[0]
            ranges = nodes_str.split('[')[1].split(']')[0].split(',')
            for item in ranges:
                if '-' in item:
                    start, end = map(int, item.split('-'))
                    nodes.extend([f"{base_name}{i}" for i in range(start, end + 1)])
                else:
                    nodes.append(f"{base_name}{item}")
        else:
            nodes = nodes_str.split(',')
        
        return nodes
    
    return []
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-j", "--jobs", help="show active jobs on the nodes", action="store_true")
    parser.add_argument("-n", "--node", help="show info for a specific node only")

    args = parser.parse_args()
    show_jobs = args.jobs
    node_filter = args.node

    node_info = get_slurm_node_info()
    
    # Filter for specific node if requested
    if node_filter:
        node_info = {node_name: info for node_name, info in node_info.items() if node_name == node_filter}
    
    if show_jobs:
        job_info = get_slurm_jobs()
        default_values = parse_slurm_conf_nodes()

    print("{:<15}{:<12}{:<10}{:<9}{:<10}".format("NODE", "CPUS", "GPUS", "MEM (G)", " | JOBS" if show_jobs else " "))

    partitions = set([info['partition'] for node_name, info in node_info.items()])
    partitions = sorted(partitions)

    global_total_cpu = 0
    global_total_gpu = 0
    global_total_mem = 0
    global_available_cpu = 0
    global_available_gpu = 0
    global_available_mem = 0
    global_total_nodes = 0

    for partition in partitions:
        info_partition = [x for x in node_info.items() if x[1]['partition'] == partition]
        for node_name, info in info_partition:
            global_total_nodes += 1
            available_cpu = int(info['cfg_tres']['cpu']) - int(info['alloc_tres']['cpu'])
            int_total_cpu = int(info['cfg_tres']['cpu'])    
            global_available_cpu += available_cpu
            global_total_cpu += int_total_cpu

            total_cpu = "\033[90m" + "/" + str(int_total_cpu) + "\033[0m"
            if available_cpu == 0:
                available_cpu = "\033[91m" + str(available_cpu) + "\033[0m"
            elif available_cpu < 0.5 * int_total_cpu:
                available_cpu = "\033[33m" + str(available_cpu) + "\033[0m"
            else:
                available_cpu = "\033[32m" + str(available_cpu) + "\033[0m"
            available_cpu = f"{available_cpu}{total_cpu}"

            available_gpu = int(info['cfg_tres']['gres/gpu']) - int(info['alloc_tres']['gres/gpu'])
            int_total_gpu = int(info['cfg_tres']['gres/gpu'])
            global_available_gpu += available_gpu
            global_total_gpu += int_total_gpu
            
            total_gpu = "\033[90m" + "/" + str(int_total_gpu) + "\033[0m"

            if available_gpu == 0:
                available_gpu = "\033[91m" + str(available_gpu) + "\033[0m"
            elif available_gpu < 0.5 * int_total_gpu:
                available_gpu = "\033[33m" + str(available_gpu) + "\033[0m"
            else:
                available_gpu = "\033[32m" + str(available_gpu) + "\033[0m"
            
            # on cpu servers replace 0/0 with -
            if int(info['cfg_tres']['gres/gpu']) == 0:
                available_gpu =  "\033[91m" + " " + "\033[0m"
                total_gpu = "\033[90m" + "-" + " " + "\033[0m"        

            available_gpu = f"{available_gpu}{total_gpu}"

            available_mem = parse_mem(info['cfg_tres']['mem']) - parse_mem(info['alloc_tres']['mem'])
            total_mem = parse_mem(info['cfg_tres']['mem'])
            global_available_mem += available_mem
            global_total_mem += total_mem

            total_mem = "\033[90m" + "/" + str(total_mem) + "\033[0m"
            if available_mem == 0:
                available_mem = "\033[91m" + str(available_mem) + "\033[0m"
            else:
                available_mem = "\033[32m" + str(available_mem) + "\033[0m"
    
            available_mem = f"{available_mem}{total_mem}"
            state = info['state']
            
            # Check if state contains IDLE, MIXED, or ALLOCATED (handles composite states like IDLE+PLANNED)
            if state != 'IDLE' and state != 'MIXED' and state != 'ALLOCATED':
                if "RESERVED" in state:
                    available_cpu = "\033[90m"  + "RESERVED" + "\033[0m" + "\033[32m" + "" + "\033[0m"
                elif "DOWN" in state:
                    available_cpu = "\033[91m"  + "DOWN" + "\033[0m" + "\033[32m" + "" + "\033[0m"
                elif "DRAINING" in state:
                    available_cpu = "\033[33m"  + "DRAINING" + "\033[0m" + "\033[32m" + "" + "\033[0m"
                elif "DRAINED" in state:
                    available_cpu = "\033[33m"  + "DRAINED" + "\033[0m" + "\033[32m" + "" + "\033[0m"
                elif "COMPLETING" in state:
                    available_cpu = "\033[33m"  + "COMPLETING" + "\033[0m" + "\033[32m" + "" + "\033[0m"
                elif "PLANNED" in state:
                    available_cpu = "\033[90m"  + "PLANNED" + "\033[0m" + "\033[32m" + "" + "\033[0m"
                else:
                    available_cpu = "\033[90m"  + state + "\033[0m" + "\033[32m" + "" + "\033[0m"
                
                available_gpu = "\033[91m"  + " " + "\033[0m" + "\033[32m" + "" + "\033[0m"
                available_mem = "\033[91m"  + " " + "\033[0m" + "\033[32m" + "" + "\033[0m"
    
            def strip_ansi(text):
                """Remove ANSI escape codes from string to get visible length."""
                ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
                return ansi_escape.sub('', text)
            
            def format_col(text, width):
                """Format text to fixed visible width, accounting for ANSI codes."""
                visible_len = len(strip_ansi(text))
                return text + ' ' * max(0, width - visible_len)
            
            # Format columns matching header: "{:<15}{:<12}{:<10}{:<9}"
            base_indent = (format_col(node_name, 15) + 
                          format_col(available_cpu, 12) + 
                          format_col(available_gpu, 10) + 
                          format_col(available_mem, 9))
            # Calculate visible width for continuation lines
            visible_indent_len = 15 + 12 + 10 + 9
            job_entries = []
            
            if show_jobs:
                # Find all jobs running on this node and get per-node allocation data
                for jobid, job_data in job_info.items():
                    if node_name in job_data.get('node_alloc', {}):
                        alloc = job_data['node_alloc'][node_name]
                        user = job_data['user']
                        cpu = str(alloc['cpus'])
                        mem = alloc['mem'] // 1000  # Convert MB to GB
                        gpu = str(alloc['gpus'])
                        gpu_idx = alloc.get('gpu_idx', '')

                        total_gpu = info['cfg_tres']['gres/gpu']

                        # Get node specs from slurm.conf
                        node_specs = default_values.get(node_name, {})
                        recommended_cpu = (node_specs.get('cpus') // int(total_gpu)) * int(gpu) if int(gpu) > 0 else int(cpu)
                        if int(gpu) > 0 and int(total_gpu) > 0:
                            recommended_cpu = node_specs.get('cpus') // int(total_gpu)
                        recommended_mem = ((node_specs.get('memory')/1000) // node_specs.get('cpus')) * int(recommended_cpu)

                        if int(cpu) <= recommended_cpu:
                            cpu = "\033[33m" + cpu + "\033[0m"
                        else:
                            cpu = "\033[91m" + cpu + "\033[0m"

                        if mem <= recommended_mem:
                            mem = "\033[33m" + str(mem) + "G" + "\033[0m"
                        else:
                            mem = "\033[91m" + str(mem) + "G" + "\033[0m"

                        if gpu == "0": #gray
                            gpu = "\033[90m" + gpu + "\033[0m"
                        else:
                            gpu = "\033[33m" + gpu + "\033[0m"

                        #bold user
                        user = "\033[1m" + user + "\033[0m"

                        # Format GPU count with IDX if available
                        if gpu_idx:
                            gpu_str = f"{gpu}({gpu_idx})"
                        else:
                            gpu_str = gpu

                        res = f"{cpu}:{gpu_str}:{mem}"
                        job_entries.append(f"{user}({res})")
            
            # Print first line with node info and first batch of jobs
            if job_entries:
                first_batch = job_entries[:3]
                out = base_indent + " | " + ", ".join(first_batch)
                print(out)
                
                # Print remaining jobs in batches of 3 with proper indentation
                indent = " " * visible_indent_len
                for i in range(3, len(job_entries), 3):
                    batch = job_entries[i:i+3]
                    print(indent + " | " + ", ".join(batch))
            else:
                print(base_indent)

if __name__ == "__main__":
    main()
