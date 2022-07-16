import argparse

def gen_file_line(l):
    line_str = "0000   "
    for i in l:
        line_str += f'{i:02x} '

    return line_str

def convert_to_hexdump(input_path, output_path):
    output_file_arr = []
    with open(input_path) as f:
        for line in f:
            tmp = list(map(int, line.split()))
            output_file_arr.append(gen_file_line(tmp))
    
    with open(output_path, "w") as f:
        for line in output_file_arr:
            f.write(line + '\n')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', '-i', dest='input_path', help='path of the decimal input file')
    parser.add_argument('--output', '-o', dest='output_path', help='path of the output file')
    args = parser.parse_args()
    
    if args.input_path == None or args.output_path == None:
        print('not sufficient flags')
        exit()

    convert_to_hexdump(args.input_path, args.output_path)