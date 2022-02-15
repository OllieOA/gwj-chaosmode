def decode_utf8(input_str):
    ascii_str = ""
    for byte_str in input_str.split(" "):
        if byte_str != "":
            ascii_str += chr(int(byte_str, 2))

    return ascii_str


def flip(bit_str):
    new_str = ""

    for bit in bit_str:
        if bit == "0":
            new_str += "1"
        elif bit == "1":
            new_str += "0"
        else:
            new_str += " "
    return new_str


def get_or(bit1, bit2):
    if bit1 == "1" or bit2 == "1":
        return "1"
    else:
        return "0"


def get_xor(bit1, bit2):
    if bit1 + bit2 in ["01", "10"]:
        return "1"
    else:
        return "0"


def get_full_or(bit_str_1, bit_str_2):
    assert len(bit_str_1) == len(bit_str_2), "NOT THE SAME LENGTH"

    new_bit_str = ""
    for i in range(len(bit_str_1)):
        new_bit_str += get_or(bit_str_1[i], bit_str_2[i])

    return new_bit_str


def get_byte_wraparound(input_str):
    print("=-" * 8)
    print("Byte-based Wraparound")
    output_binary = ""
    for bit_string in input_str.split(" "):
        new_string = ""

        for i in range(len(bit_string)):
            try:
                new_string += get_or(bit_string[i], bit_string[i + 1])
            except IndexError:
                new_string += get_or(bit_string[i], bit_string[0])
        output_binary += new_string + " "
    print(output_binary)
    print(decode_utf8(output_binary))
    return output_binary


def get_full_xor(bit_str_1, bit_str_2):
    assert len(bit_str_1) == len(bit_str_2), "NOT THE SAME LENGTH"

    new_bit_str = ""
    for i in range(len(bit_str_1)):
        new_bit_str += get_xor(bit_str_1[i], bit_str_2[i])

    return new_bit_str


def get_byte_wraparound_xor(input_str):
    print("=-" * 8)
    print("Byte-based Wraparound (XOR)")
    output_binary = ""
    for bit_string in input_str.split(" "):
        new_string = ""

        for i in range(len(bit_string)):
            try:
                new_string += get_xor(bit_string[i], bit_string[i + 1])
            except IndexError:
                new_string += get_xor(bit_string[i], bit_string[0])
        output_binary += new_string + " "
    print(output_binary)
    print(decode_utf8(output_binary))
    return output_binary


def get_full_wraparound(input_str):
    print("=-" * 8)
    print("Full Wraparound")
    split_input_bin = input_str.split(" ")
    full_input_or = ""
    for i in range(len(split_input_bin)):
        new_bit_str = ""

        try:
            new_bit_str += get_full_or(split_input_bin[i], split_input_bin[i + 1])
        except IndexError:
            new_bit_str += get_full_or(split_input_bin[i], split_input_bin[0])

        full_input_or += new_bit_str + " "
    print(full_input_or)
    print(decode_utf8(full_input_or))
    return full_input_or


def get_full_wraparound_xor(input_str):
    print("=-" * 8)
    print("Full Wraparound (XOR)")
    split_input_bin = input_str.split(" ")
    full_input_or = ""
    for i in range(len(split_input_bin)):
        new_bit_str = ""

        try:
            new_bit_str += get_full_xor(split_input_bin[i], split_input_bin[i + 1])
        except IndexError:
            new_bit_str += get_full_xor(split_input_bin[i], split_input_bin[0])

        full_input_or += new_bit_str + " "
    print(full_input_or)
    print(decode_utf8(full_input_or))
    return full_input_or


def get_1bit_sprite(input_str):
    for bin_str in input_str.split(" "):
        # TEMP ADDING MIRROR
        bin_to_print = bin_str + bin_str[::-1]
        print(bin_to_print.replace("1", " ").replace("0", chr(9608)))


input_binary = "11111010 11001000 11001111 10001101 11000010 11001011 10001101 11000001 11000100 11001000 11011110"
flipped_input = flip(input_binary)
reversed_input = input_binary[::-1]
flipped_reversed_input = flip(reversed_input)

print("== Direct Input")
get_1bit_sprite(get_byte_wraparound(input_binary))
get_1bit_sprite(get_full_wraparound(input_binary))
get_1bit_sprite(get_byte_wraparound_xor(input_binary))
get_1bit_sprite(get_full_wraparound_xor(input_binary))

print("\n== Flipped Input")
get_1bit_sprite(get_byte_wraparound(flipped_input))
get_1bit_sprite(get_full_wraparound(flipped_input))
get_1bit_sprite(get_byte_wraparound_xor(flipped_input))
get_1bit_sprite(get_full_wraparound_xor(flipped_input))

print("\n== Reversed Input")
get_1bit_sprite(get_byte_wraparound(reversed_input))
get_1bit_sprite(get_full_wraparound(reversed_input))
get_1bit_sprite(get_byte_wraparound_xor(reversed_input))
get_1bit_sprite(get_full_wraparound_xor(reversed_input))

print("\n== Flipped Reversed Input")
get_1bit_sprite(get_byte_wraparound(flipped_reversed_input))
get_1bit_sprite(get_full_wraparound(flipped_reversed_input))
get_1bit_sprite(get_byte_wraparound_xor(flipped_reversed_input))
get_1bit_sprite(get_full_wraparound_xor(flipped_reversed_input))
