#!/usr/bin/env python3
import sys, json, csv

TARGET_MESSAGE = "prove_shard_with_data finished"

def main():
    w = csv.writer(sys.stdout)
    w.writerow(["shard_index", "total_ms", "total_cells", "bus_interactions"])

    time_sum = 0
    cells_sum = 0
    bus_interactions_sum = 0
    shard_index = 0

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            # Not JSON (e.g., cargo noise) -> skip
            continue

        if obj.get("message") != TARGET_MESSAGE:
            continue

        total_ms = obj.get("total_ms")
        total_cells = obj.get("total_cells")
        bus_interactions = obj.get("bus_interactions")

        total_ms_num = int(total_ms)
        total_cells_num = int(total_cells)
        bus_interactions_num = int(bus_interactions)

        time_sum += total_ms_num
        cells_sum += total_cells_num
        bus_interactions_sum += bus_interactions_num

        w.writerow([shard_index, total_ms_num, total_cells_num, bus_interactions_num])
        shard_index += 1

    # Write the totals row
    w.writerow(["total", time_sum, cells_sum, bus_interactions_sum])

if __name__ == "__main__":
    main()