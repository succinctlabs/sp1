import argparse

class Labels:
    def __init__(self, label):
        self.label = label
        self.children = {}
        self.num_cycles = 0

class Stats:
    def __init__(self):
        self.num_total_cycles = 0
        self.num_calls = 0


def parse_file(tracking_filename, top_level_label):
    top_level_labels = []
    label_stack = []

    with open(tracking_filename, 'r') as tracking_file:
        for line in tracking_file:
            is_label_line = False
            is_cycle_line = False
            line_label = None
            cycle_count = 0

            if '┌╴' in line:
                line_label = line.split('┌╴')[1]
                is_label_line = True

            if '└─' in line:
                cycle_count = int(line.split('└─')[1])
                is_cycle_line = True

            if is_label_line:
                # If there are no labels in the stack, ignore this line if's not the top level label
                # If it is equal to the top level label, then push it onto the stack
                if len(label_stack) == 0:
                    if top_level_label != line_label:
                        continue
                    else:
                        label = Labels(line_label)
                        label_stack.append(label)
                else: # The stack is not empty.  Add to the stack.
                    label = Labels(line_label)
                    label_stack.append(label)

            if is_cycle_line:
                if len(label_stack) == 0:
                    continue

                label = label_stack.pop()
                label.num_cycles += cycle_count

                if len(label_stack) > 0:
                    # Add to the parent's children
                    parent_label = label_stack[-1]
                    if label.label not in parent_label.children:
                        parent_label.children[label.label] = Stats()
    
                    parent_label.children[label.label].num_calls += 1
                    parent_label.children[label.label].num_total_cycles += label.num_cycles
                else:
                    top_level_labels.append(label)

    return top_level_labels

def main():
    parser = argparse.ArgumentParser(description='Aggregate cycle tracker numbers.')

    parser.add_argument('tracking_filename', type=str, help='Tracking filename')
    parser.add_argument('top_level_label', type=str, help='Top level table')

    # Parse the command-line arguments
    args = parser.parse_args()

    parse_file(args.tracking_filename, args.top_level_label)



if __name__ == '__main__':
    main()


