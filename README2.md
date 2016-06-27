opmsg contrib
=============

This document covers `opcoin`. For `opmux` please refer to the MUA
chapter inside the main README.md.


opcoin
------

__Note: Do not use BTC addresses where you hold a lot of unspent outputs. Rather just import private
keys from your wallet with little amount of money on it, to reduce risk of compromise. Your opmsg keys
(and so your BTC imported opcoin keys) will be stored unencrypted on disk. I am assuming you are using FDE anyways,
to protect your keystore. So again, do not use BTC addresses which own much money. After all,
this is an experimentel feature, driving on the bitcoin network as a web-of-trust. At best,
create a fresh BTC address for opcoins. You may still use them to proof ownership with micro
transactions.__



1. Importing pubkeys
--------------------

Bitcoins use ECC with curve __secp256k1__. As ECC is used, its easy for opmsg
to work with it and to import it into the keystore and to en/decrypt messages,
using bitcoin keys.

You can use `opcoin` to import public bitcoin keys by using the `--public` switch.
As argument to `--public` you have to pass the hex encoded public portion of a bitcoin key,
which either starts with `02`, `03` (compressed format) or `04` (uncompressed).

These public keys may be found inside any bitcoin _Pay-to-Public-Key-Hash (P2PKH)_ transaction,
more specifically inside its locking script (sometimes called input script). Keep looking
for hex strings starting with 02, 03 or 04. Bitcoin addresses for P2PKH transactions start
with a `1`. During import, you have to add the `--name` parameter, pointing to the
bitcoin address. This makes sure that you dont accidently import a wrong key. __Check that the
bitcoin address (name) matches the string that you actually want to import__. The bitcoin address
becomes the name of that opmsg persona and
`opmsg -l` will later list it as name, so you immediately see where it is coming from.

If the transaction is evaulated as valid by the bitcoin network and becomes part of the blockchain,
you have (very) strong evidence that your peer holds the private key. You can tell your peer
to transfer some small amounts of BTC to your address from the address you imported, to check
that you are talking to the right person.

After import, link this opcoin persona to the source persona you want to use for op messenging.



2. Importing private keys
-------------------------

You have to export/dump the bitcoin key in question out of your (unlocked) wallet.
This will give you a WIF encoded string - starting with `K`, `L` (compressed) or `5` (uncompressed) -
consisting of your private key. It is not necessary to add a `--public` key, as this
is derived from the WIF string which you directly add to the `--private` switch.
Again this time, the address has to be given via `--name` in order to validate you were
refering to the right BTC address.


Thats basically it. You can now use the opcoin personas as any other personas with opmsg.
The main idea behind it is to use the public ledger with some micro transactions as a proof
that a certain persona holds a key (proofing it by sending you some satoshis of secret amount
to your account).


