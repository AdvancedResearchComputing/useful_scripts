#!/usr/bin/env python3
"""Parse and pretty-print a summary of quota.json allocations."""

import json
import re
import sys

# Warning: quota values are not updated in real time and may take a few hours to refresh.
# USER             FILESYS/SET                          DATA (GB)    QUOTA (GB)  FILES      QUOTA      NOTE
# nml5566          /home                                14.9         640         -          -
#
# nml5566          /projects/nml_cf_test                0.0          50000       6          10485760
# nml5566          /projects/arcadm                     4070.0       10000       2580806    10485760
#
# USER             ALLOCATION                           CLUSTER      QUOTA (hrs) LEFT (hrs) STATUS     NOTE
# nml5566          statiwave                            tinkercliffs 1000000     999995     Active
#                                                       falcon       1000000     1000000    Active
#                                                       owl          1000000     1000000    Active
# nml5566          iwave2                               tinkercliffs 1000000     1000000
#                                                       falcon       1000000     1000000
#                                                       owl          1000000     1000000
# nml5566          arcadm                               tinkercliffs 750000      750000
#                                                       falcon       750000      750000
#                                                       owl          750000      750000
# nml5566          nml_arcadm_test                      tinkercliffs 800000      800000
#                                                       falcon       800000      800000
#                                                       owl          800000      800000
# nml5566          nml_cf_test                          tinkercliffs 800000      799999     Expired    Allocation has expired.
#                                                       falcon       800000      800000     Expired    Allocation has expired.
#                                                       owl          800000      800000     Expired    Allocation has expired.


def get_attr(attributes, attr_type):
    """Return all values for a given allocation_attribute_type."""
    return [a["value"] for a in attributes if a["allocation_attribute_type"] == attr_type]


def summarize_compute_allocation(alloc):
    attrs = alloc["allocation_attribute"]
    lines = [ ]

    # Compute allocations
    account = get_attr(attrs, "slurm_account_name")
    if account:
        lines.append(account[0])

    billing_hrs = 0
    specs = get_attr(attrs, "slurm_specs")
    if specs:
        for spec in specs:
            items = spec.split("GrpTRESMins=billing=")
            if len(items) > 1:
                billing_hrs = int(int(items[1]) / 60)

    usage = get_attr(attrs, "compute_usage")
    if usage:
        items = usage[0].split("<br>")
        for count, line in enumerate(items[1:]):
            (cluster, cluster_usage) = line.split(": <i>")
            digits = re.findall(r'[\d.]+', cluster_usage)
            used = float(digits[0])
            total = float(digits[1])
            cluster_used_hrs = float(cluster_usage.split('/')[0])
            left = int(billing_hrs - (billing_hrs * used / total))
            if count != 0:
                lines.append(f"")
            lines.append(f"{cluster}|{billing_hrs}|{left}|{alloc['status']}|\n")

    else:
        lines.append(f"||||\n")

    return "|".join(lines)


def summarize_storage_allocation(alloc):
    attrs = alloc["allocation_attribute"]
    lines = [ ]

    # Compute allocations
    account = get_attr(attrs, "storage_used")
    if account:
        lines.append(account[0])

    # specs = get_attr(attrs, "slurm_specs")
    # for spec in specs:
    #     lines.append(f"  Spec     : {spec}")

    # Storage allocations
    storage_group = get_attr(attrs, "Storage_Group_Name")
    if storage_group:
        lines.append(storage_group[0])

    usage = get_attr(attrs, "storage_usage")
    if usage:
        data_gb = float(usage[0].split('/')[0]) * 1000
        lines.append(str(round(data_gb,1)))

    quota = get_attr(attrs, "Storage Quota (GB)")
    if quota:
        lines.append(quota[0])

    return "|".join(lines)


def main(path="quota.json"):
    with open(path) as f:
        allocations = json.load(f)

    pid = "nml5566"
    compute_free = [a for a in allocations if a["resource"] == "Compute (Free)"]
    project_free = [a for a in allocations if a["resource"] == "Project (Free)"]

    print("USER|ALLOCATION|CLUSTER|QUOTA (hrs)|LEFT (hrs)|STATUS|NOTE")
    for alloc in compute_free:
        print(pid + "|" + summarize_compute_allocation(alloc))
    print()
    print("USER|FILESYS/SET|DATA (GB)|QUOTA (GB)|FILES|QUOTA|NOTE")
    for alloc in project_free:
        print(pid + "|" + summarize_storage_allocation(alloc))


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "quota.json"
    main(path)
