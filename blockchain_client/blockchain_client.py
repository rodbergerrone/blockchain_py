"""
title           : blockchain_client.py
description     : A blockchain user backend implementation in Python that provides following features:
                  - wallet generator using public/private key encryption (based on RSA algorithm)
                  - making transaction with RSA encryption
                  - viewing transactions made
                  - exchanging coins for FIAT currency (e.g. EURO) in cryptoATM - pending implementation
author          : Roger Burek-Bors with instruction from Dr Zakwan Jaroucheh, the lecturer of <<Build a Blockchain &
                  Cryptocurrency using Python>> on Udemy
date_created    : 2020-12-22
version         : 0.1
usage           : The script runs locally therefore to simulate various nodes it needs a specified port to listen to.
                  You can run following instances:
                  - python blockchain_client.py
                  - python blockchain_client.py -p 8080
                  - python blockchain_client.py --port 8080
python_version  : 3.7
"""

import binascii
import Crypto
import Crypto.Random
from flask import Flask, request, jsonify, render_template
from collections import OrderedDict
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5


class Transaction:

    def __init__(self, sender_public_key, sender_private_key, recipient_public_key, amount):
        self.sender_public_key = sender_public_key
        self.sender_private_key = sender_private_key
        self.recipient_public_key = recipient_public_key
        self.amount = amount

    def to_dict(self):
        return OrderedDict({
            'sender_public_key': self.sender_public_key,
            'recipient_public_key': self.recipient_public_key,
            'amount': self.amount,
        })

    def sign_transaction(self):
        private_key = RSA.import_key(binascii.unhexlify(self.sender_private_key))
        signer = PKCS1_v1_5.new(private_key)
        h = SHA.new(str(self.to_dict()).encode('utf8'))
        return binascii.hexlify(signer.sign(h)).decode('ascii')


app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
    sender_public_key = request.form['sender_public_key']
    sender_private_key = request.form['sender_private_key']
    recipient_public_key = request.form['recipient_public_key']
    amount = request.form['amount']

    transaction = Transaction(sender_public_key, sender_private_key, recipient_public_key, amount)

    response = {'transaction': transaction.to_dict(),
                'signature': transaction.sign_transaction()}

    return jsonify(response), 200


@app.route('/make/transaction')
def make_transaction():
    return render_template('make_transaction.html')


@app.route('/view/transactions')
def view_transactions():
    return render_template('view_transactions.html')


# TODO: sell coin in cryptoATM, while generating new wallet give 100 coins


@app.route('/wallet/new')
def new_wallet():
    random_gen = Crypto.Random.new().read
    private_key = RSA.generate(1024, random_gen)
    public_key = private_key.publickey()

    response = {
        'private_key': binascii.hexlify(private_key.export_key(format('DER'))).decode('ascii'),
        'public_key': binascii.hexlify(public_key.export_key(format('DER'))).decode('ascii')
    }

    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8081, type=int, help="port to listen to")
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port, debug=True)
