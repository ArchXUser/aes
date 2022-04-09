#include <string>
#include <sstream>
#include <iomanip>

#include "aes256.hpp"

std::string AES256::encrypt(std::string plaintext, uint8_t *key)
{
    size_t msg_len = plaintext.length() + (16 - plaintext.length()%16);
    if (plaintext.length() % 16 == 0) {
        msg_len -= 16;
    }
    size_t block_num = msg_len / 16;

    std::stringstream ss;
    ss << plaintext << std::setw(msg_len) << "";
    std::string block[block_num];
    std::string ciphertext;

    for (size_t i = 0, k = 0; i < msg_len; i += 16, k++) {
        if (k < block_num) {
            block[k] = ss.str().substr(i, 16);
        }
    }

    for(size_t i = 0; i < block_num; i++) {
        ciphertext += encryptBlock(block[i], key);
    }
    return ciphertext;
}

std::string AES256::decrypt(std::string ciphertext, byte_t *key)
{
    std::string block[ciphertext.length()/32];
    int k=-1;
    std::string plaintext;

    for(size_t i = 0; i < ciphertext.length(); i += 32) {
        k++;
        block[k] = ciphertext.substr(i, 32);
    }
    k = ciphertext.length()/32;
    for(int i = 0; i < k; i++) {
        plaintext += decryptBlock(block[i], key);
    }
    return plaintext;
}

word_t AES256::rotWord(word_t x)
{
    return (x<<8)|((x>>32)-8);
}

word_t AES256::subInt(word_t y)
{
    return sbox[(y&0xff)>>4][y&0x0fU];
}

word_t AES256::subWord(word_t x)
{
    return (subInt(x>>24)<<24) | (subInt((x>>16)&0xff)<<16) |
           (subInt((x>>8)&0xff)<<8) | (subInt(x&0xff));
}

void AES256::keyExpansion(byte_t *key)
{
    word_t temp;
    int i = 0;

    do {
        w[i] = ((word_t)key[4*i]<<24) | (key[4*i+1]<<16) |
               (key[4*i+2]<<8) | key[4*i+3];
        i++;
    } while (i < Nk);

    i = Nk;

    word_t tmp_rcon[11];
    for (int c = 1; c < 11; c++) {
        tmp_rcon[c] = (uint8_t)(rcon[c] & 0xff)<<24;
    }

    while (i < Nb * (Nr+1)) {
        temp = w[i-1];
        if (i % Nk == 0) {
            // (word_t)
            temp = subWord(rotWord(temp)) ^ tmp_rcon[i/Nk];
        }
        else if (Nk > 6 && i % Nk == 4) {
            temp = subWord(temp);
        }
        w[i] = w[i-Nk] ^ temp;
        i++;
    }
}

void AES256::addRoundKey(int round)
{
    for (int c = 0; c < Nb; c++) {
        word_t w_index = w[round*4 + c];

        state[0][c] ^= (w_index >> 24) & 0xff;
        state[1][c] ^= (w_index >> 16) & 0xff;
        state[2][c] ^= (w_index >> 8) & 0xff;
        state[3][c] ^= w_index & 0xff;
    }
}

void AES256::shiftRows()
{
    byte_t tmp[4][Nb];

    for(int r = 1; r < 4; r++) {
        for(int c = 0; c < Nb; c++)
            tmp[r][c] = state[r][c];
    }

    for(int r = 1; r < 4; r++) {
        for(int c = 0; c < Nb; c++)
            state[r][c] = tmp[r][(r+c) % 4];
    }
}

void AES256::subBytes()
{
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < Nb; c++) {
            byte_t low_mask = state[r][c] & 0x0fU;
            byte_t high_mask = state[r][c] >> 4;

            state[r][c] = sbox[high_mask][low_mask];
        }
    }
}

void AES256::mixColumns()
{
    auto xtime = [] (byte_t x)
    {
        return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
    };

    for(int c = 0; c < Nb; c++) {
        byte_t column[4] = {
            state[0][c],
            state[1][c],
            state[2][c],
            state[3][c]
        };

        byte_t tmp1 = (column[0] ^ column[1] ^ column[2] ^ column[3]);
        byte_t tmp2 = (column[0] ^ column[1]) ; tmp2 = xtime(tmp2);

        state[0][c] ^=  (tmp2 ^ tmp1);
        tmp2 =       (column[1] ^ column[2]) ; tmp2 = xtime(tmp2);
        state[1][c] ^=  (tmp2 ^ tmp1);
        tmp2 =       (column[2] ^ column[3]) ; tmp2 = xtime(tmp2);
        state[2][c] ^=  (tmp2 ^ tmp1);
        tmp2 =       (column[3] ^ column[0]) ; tmp2 = xtime(tmp2);
        state[3][c] ^=  (tmp2 ^ tmp1);
    }
}

void AES256::cipher(byte_t *in, byte_t *out)
{
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < Nb; c++)
            state[r][c] = in[r + 4*c];
    }

    addRoundKey(0);
    for(int round = 1; round < Nr; round++) {
        subBytes();
        shiftRows();
        mixColumns();
        addRoundKey(round);
    }
    subBytes();
    shiftRows();
    addRoundKey(Nr);

    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < Nb; c++)
            out[r + 4*c] = state[r][c];
    }
}

std::string AES256::encryptBlock(std::string block, byte_t *key)
{
    byte_t in[4*Nb];
    byte_t out[4*Nb];

    for (int i = 0; i < 4*Nb; i++) {
        in[i] = block[i];
    }

    keyExpansion(key);
    cipher(in, out);

    std::stringstream ss;
    for (int i = 0; i < 4*Nb; i++) {
        ss << std::setw(2) << std::hex
           << (halfword_t)out[i];
    }
    return ss.str();
}

void AES256::invShiftRows()
{
    byte_t tmp[4][Nb];

    for (int r = 1; r < 4; r++) {
        for (int c = 0; c < Nb; c++)
            tmp[r][c] = state[r][c];
    }

    for (int r = 1; r < 4; r++) {
        for (int c = 0; c < Nb; c++)
            state[r][(r+c) % 4] = tmp[r][c];
    }
}

void AES256::invSubBytes()
{
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < Nb; c++) {
            byte_t low_mask = state[r][c] & 0x0fU;
            byte_t high_mask = state[r][c] >> 4;

            state[r][c] = inv_sbox[high_mask][low_mask];
        }
    }
}


byte_t AES256::GF256(byte_t x, byte_t y)
{
    byte_t p = 0;

    for(int i = 0; i < 8; i++) {
        p ^= (byte_t)(-(y&1)&x);
        x = (byte_t)((x<<1) ^ (0x11b & -((x>>7)&1)));
        y >>= 1;
    }
    return p;
}

void AES256::invMixColumns()
{
    byte_t s_mixarr[4] = {0x0e, 0x0b, 0x0d, 0x09};

    for(int c = 0; c < Nb; c++) {
        byte_t column[4] = {
            state[0][c],
            state[1][c],
            state[2][c],
            state[3][c]
        };

        state[0][c] = (GF256(column[0], s_mixarr[0]) ^
                       GF256(column[1], s_mixarr[1]) ^
                       GF256(column[2], s_mixarr[2]) ^
                       GF256(column[3], s_mixarr[3]));
        state[1][c] = (GF256(column[0], s_mixarr[3]) ^
                       GF256(column[1], s_mixarr[0]) ^
                       GF256(column[2], s_mixarr[1]) ^
                       GF256(column[3], s_mixarr[2]));
        state[2][c] = (GF256(column[0], s_mixarr[2]) ^
                       GF256(column[1], s_mixarr[3]) ^
                       GF256(column[2], s_mixarr[0]) ^
                       GF256(column[3], s_mixarr[1]));
        state[3][c] = (GF256(column[0], s_mixarr[1]) ^
                       GF256(column[1], s_mixarr[2]) ^
                       GF256(column[2], s_mixarr[3]) ^
                       GF256(column[3], s_mixarr[0]));
    }
}

void AES256::invCipher(byte_t *in, byte_t *out)
{
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < Nb; c++)
            state[r][c] = in[r + 4*c];
    }

    addRoundKey(Nr);
    for (int round = Nr-1; round > 0; round--) {
        invShiftRows();
        invSubBytes();
        addRoundKey(round);
        invMixColumns();
    }
    invShiftRows();
    invSubBytes();
    addRoundKey(0);

    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < Nb; c++)
            out[r + 4*c] = state[r][c];
    }
}

std::string AES256::decryptBlock(std::string block, byte_t *key)
{
    byte_t in[4*Nb];
    byte_t out[4*Nb];

    std::stringstream conv;

    for (size_t i = 0; i < block.length(); i += 2) {
        conv << std::hex << block.substr(i, 2);
        word_t uint8;
        conv >> uint8;
        in[i/2] = uint8 & 0xffU;
        conv.str(std::string());
        conv.clear();
    }

    keyExpansion(key);
    invCipher(in, out);
    std::string str;

    for (int i = 0; i < 4*Nb; i++) {
        str += out[i];
    }
    return str;
}
