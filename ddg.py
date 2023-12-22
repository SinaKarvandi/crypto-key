import angr
import re

def create_pre_pdg(binary_file, hex_integers_list):
    b = angr.Project(binary_file, load_options={"auto_load_libs": False})
    obj = b.loader.main_object.min_addr
    print(hex(obj))
    cfg = b.analyses.CFGEmulated(keep_state=True, state_add_options=angr.sim_options.refs)
    address_ins = {}
    for n in cfg.graph.nodes():
        try:
            if n.block is not None:
                for ins in n.block.capstone.insns:
                    address_ins[ins.address] = ins

        except:
            continue

    ddg = b.analyses.DDG(cfg) # , start=func_address

    for node1, node2 in ddg.graph.edges():
        start_addr = node1.ins_addr
        end_addr = node2.ins_addr
        if (
            start_addr in address_ins
            and end_addr in address_ins
            and start_addr != end_addr
        ):
            # print(address_ins[start_addr])
            # print(address_ins[end_addr])
            # print("********************")

            for item in hex_integers_list:
                if (start_addr & 0xffff) == item or (end_addr & 0xffff) == item :
                    print(address_ins[start_addr])
                    print(address_ins[end_addr])
                    print("********************")
                    break



def extract_hexadecimal_strings(input_string):
    # Define a regular expression pattern to match hexadecimal strings
    pattern = r'([0-9a-fA-F]+)'

    # Find all matches in the input string using the pattern
    matches = re.findall(pattern, input_string)

    # Convert hexadecimal strings to integers and store them in a list
    hex_integers = [int(hex_string, 16) for hex_string in matches]

    return hex_integers

def process_file(file_path):
    hex_integers_list = []

    # Open the file and read it line by line
    with open(file_path, 'r') as file:
        for line in file:
            # Extract hexadecimal strings from each line
            hex_integers_list.extend(extract_hexadecimal_strings(line))

    return hex_integers_list

def main():

    # Example file path, replace with the path to your actual file
    file_path = 'accesses.txt'

    # Process the file and get the list of integers
    hex_integers_list = process_file(file_path)

    # Print the list of integers
    print([hex(x) for x in hex_integers_list])
    
    create_pre_pdg("C:\\Users\\sina\\Desktop\\VUSec\\SimpleAesCrypt\\Release\\SimpleAesCrypt.exe", hex_integers_list)

if __name__ == "__main__":
    main()

