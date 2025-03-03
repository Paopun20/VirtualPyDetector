import string as chars

# Organizing different character sets into a list
char_sets = [
    list(chars.ascii_letters),
    list(chars.digits),
    list(chars.punctuation),
    list(chars.whitespace),
    list(chars.hexdigits),
    list(chars.octdigits),
    list(chars.printable)
]

# Iterating through each character set and printing characters
for char_list_index in range(len(char_sets)):
    for char_index in range(len(char_sets[char_list_index])):
        print(char_sets[char_list_index][char_index], end="")
