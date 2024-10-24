import sys
alpha = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'

alpha_index = {k:v for k, v in enumerate(alpha)}
r_alpha_index = {v:k for k,v in enumerate(alpha)}

#print(alpha_index)
#print(r_alpha_index)

def letter_to_index(letter):
    if letter in alpha:
        return r_alpha_index[letter]
    return -1

def index_to_letter(index):
    if 0<= index <len(alpha):
        return alpha_index[index]
    return -1


#print(letter_to_index('c'))
#print(index_to_letter(2))

def vigenere_index(key_letter,plaintext_letter):
    p = letter_to_index(plaintext_letter)
    k = letter_to_index(key_letter)
    #print(p, k)
    c = (p + k) % len(alpha)
    return index_to_letter(c)

def encrypt_vigenere(key, plaintext):
    cipher_text = []
    for i, l in enumerate(plaintext):
        if l == ' ':
            cipher_text.append(' ')
        else:
            cipher_text.append(vigenere_index(key[i % len(key)], l))
    return ''. join(cipher_text)

def r_vigenere_index(key_letter,cipher_letter):
    c = letter_to_index(cipher_letter)
    k = letter_to_index(key_letter)
    p = (c -  k + len(alpha)) % len(alpha)
    return index_to_letter(p)

def decrypt_vigenere(key, ciphertext):
    plain_text = []
    for i, l in enumerate(ciphertext):
        if l == ' ':
            plain_text.append(' ')
        else:
            plain_text.append(r_vigenere_index(key[i %len(key)], l))
    return ''. join(plain_text)

def get_vigenere_sq(alpha):
    rows = []
    for i in range(len(alpha)):
        if i == 0:
            row = ' ' + alpha[i:] + alpha[:i]
            rows.append(list( row ) )
        row = alpha[i] + alpha[i:]+alpha[:i]
        rows.append( list( row) )
    return rows

def pretty_print_vigenere(vig_list):
    for i, row in enumerate(vig_list):
        print(f'|{" | ".join(row)} |')
        if i == 0:
            print("|"+"---|"*len(row))

def menu_encryption(key, encrypted_text):
    message = input("give me something to encrypt:")
    encrypted_text.append(encrypt_vigenere(key, message))

def menu_dump(encrypted_text):
    for enc_text in encrypted_text:
        print(enc_text)

def menu_decrypt(key, encrypted_text):
    for enc_text in encrypted_text:
        print(decrypt_vigenere(key,enc_text))

def execute(menu):
    while True:
        for i in range(0, len(menu) - 1):
            print(menu[i][0])
        try:
            choice = int(input(f'make your choice{menu[-1]}:'))
            if choice in menu[-1]:
                choice -= 1
                menu[choice][1](*menu[choice][2])
            else:
                raise ValueError
        except ValueError:
            print(f'invalid choice choose one of {menu[-1]}')

def main ():
    print(alpha_index)
    key = 'oni'
    vig_list = get_vigenere_sq(alpha)
    encrypted_text = []
    menu = [
        ['1).Encrypt', menu_encryption, (key, encrypted_text)],
        ['2).Decrypt', menu_decrypt, (key, encrypted_text)],
        ['3).Dump Encrypted Text', menu_dump, (encrypted_text,)],
        ['4).Quit',sys.exit,(0,)],
        [1,2,3,4]
    ]
    #print(encrypted_text)
    #print(vig_list) # works as intended
    #print(pretty_print_vigenere(vig_list)) # haven't written the code for this yet
    #print(letter_to_index('z')) #25
    #print(letter_to_index('Z')) #51
    #print(vigenere_index('d','T'))
    #print (encrypt_vigenere(key,'beware the night parade')) #works
    #print(r_vigenere_index('a', 'h'))
    #print(decrypt_vigenere(key, encrypt_vigenere(key, 'beware the night parade')))# works
    execute(menu)

if __name__ =='__main__':
    main()