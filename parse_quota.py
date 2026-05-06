#!/usr/bin/env python3
"""Parse and pretty-print a summary of quota.json allocations."""

import json
import sys

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
    specs = get_attr(attrs, "slurm_specs") + get_attr(attrs, "slurm_user_specs")
    for spec in specs:
        items = spec.split("GrpTRESMins=billing=")
        if len(items) > 1:
            billing_hrs = int(int(items[1]) / 60)

    rawusage = get_attr(attrs, "slurm_rawusage")
    if rawusage:
        for count, raw in enumerate(rawusage):
            cluster, used_secs_str = raw.split("=")
            left = billing_hrs - int(used_secs_str) // 3600
            if count != 0:
                lines.append("")
            lines.append(f"{cluster}|{billing_hrs}|{left}|{alloc['status']}|\n")
    else:
        lines.append(f"||||\n")

    return "|".join(lines)


def summarize_storage_allocation(alloc):
    attrs = alloc["allocation_attribute"]
    lines = [ ]

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
