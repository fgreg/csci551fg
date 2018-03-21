# Copyright 2018, Frank Greguska, All rights reserved.
"""
Functions in this file:
    onion_encrypt
    onion_decrypt
    new_key
"""
import os
import struct

from Crypto.Cipher import AES

_IV = os.urandom(AES.block_size)


def onion_encrypt(keys, data):
    cipher = data
    for key in keys:
        aes = AES.new(key, AES.MODE_CFB, _IV)
        cipher = aes.encrypt(cipher)
    return cipher


def onion_decrypt(key, cipher):
    aes = AES.new(key, AES.MODE_CFB, _IV)
    return aes.decrypt(cipher)


def new_key(router_id):
    return bytes(
        x ^ y for x, y in zip(struct.pack("!16s", os.urandom(16)), struct.pack("!16s", bytes([router_id] * 16))))
