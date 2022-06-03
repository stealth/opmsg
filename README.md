opmsg
=====

[![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=9MVF8BRMX2CWA)

A gpg alternative
-----------------

_opmsg_ is a replacement for _gpg_ which can encrypt/sign/verify
your mails or create/verify detached signatures of local files.
Even though the _opmsg_ output looks similar, the concept is entirely
different.

Features:

* Perfect Forward Secrecy (PFS) by means of ECDH or DH Kex
* native EC or RSA fallback if no (EC)DH keys left
* fully compliant to existing SMTP/IMAP/POP etc. standards;
  no need to touch any mail daemon/client/agent code
* signing messages is mandatory
* OTR-like deniable signatures if demanded
* easy creation and throw-away of ids
* support for 1:1 key bindings to auto-select source key per destination
* adds the possibility to (re-)route messages different
  from mail address to defeat meta data collection
* configurable, well-established hash and crypto algorithms
  and key lengths (RSA, DH, ECC, AES, Chacha)
* straight forward and open key storage, basically also managable via
  `cat`, `shred -u` and `ls` on the cmdline
* seamless mutt integration
* Key format suitable for easy use with QR-codes
* optional cross-domain ECDH Kex
* PQC-safe operations mode if desired


_opmsg_ builds fine with any of the OpenSSL, LibreSSL and BoringSSL libcrypto libraries.
Building against BoringSSL is not recommended due to missing blowfish and ripemd algorithms.

You can use various transports with _opmsg_ such as Mail or [drops](https://github.com/stealth/drops).
Keys can be exchanged via mail, brainkeys or [QR codes](https://github.com/stealth/opmsg-qr).

Build
-----

_opmsg_ requires the crypto primitives from _OpenSSL_. Just relax, its
not using the SSL/TLS proto, just the ciphering and hash algorithms.
For standard _Linux_ distros, just type `make`.

The compilation requires a C++ compiler that supports `-std=c++11`.
This can be configured with e.g. `make CXX=eg++` on _OpenBSD_.

This project supports both `BN_GENCB_new` and `BN_GENCB` for big number
generation. To disable `BN_GENCB_new`, set `HAVE_BN_GENCB_NEW` to false:
`make DEFS=-DHAVE_BN_GENCB_NEW=0`. So on _OpenBSD_, you would run
`make CXX=eg++ DEFS=-DHAVE_BN_GENCB_NEW=0`. On _OSX_ you should install
your own _OpenSSL_, as Apple marks _OpenSSL_ as deprecated in favor of their own
crypto libs. You may also set all these options in the `Makefile`.

It successfully builds on _Linux_, _OSX_, _OpenBSD_ and probably a lot of others
(_Solaris_, _FreeBSD_,...).


```
$ cd src
$ make
[...]
$ cp build/opmsg /usr/local/bin/
$ mkdir ~/.opmsg && touch ~/.opmsg/config
$ opmsg

opmsg: version=1.84 (C) 2021 Sebastian Krahmer: https://github.com/stealth/opmsg


Usage: opmsg [--confdir dir] [--native] [--encrypt dst-ID] [--decrypt] [--sign]
	[--verify file] <--persona ID> [--import] [--list] [--listpgp]
	[--short] [--long] [--split] [--new(ec)p] [--newdhp] [--brainkey1/2]
	[--salt1/2 slt] [--calgo name] [--phash name [--name name] [--in infile]
	[--out outfile] [--link target id] [--deniable] [--burn]

	--confdir,	-c	(must come first) defaults to ~/.opmsg
	--native,	-R	EC/RSA override (dont use existing (EC)DH keys)
	--encrypt,	-E	recipients persona hex id (-i to -o, needs -P)
	--decrypt,	-D	decrypt --in to --out
	--sign,		-S	create detached signature file from -i via -P
	--verify,	-V	vrfy hash contained in detached file against -i
	--persona,	-P	your persona hex id as used for signing
	--import,	-I	import new persona from --in
	--list,		-l	list all personas
	--listpgp,	-L	list personas in PGP format (for mutt etc.)
	--short			short view of hex ids
	--long			long view of hex ids
	--split			split view of hex ids
	--newp,		-N	create new RSA persona (should add --name)
	--newecp		create new EC persona (should add --name)
	--deniable		when create/import personas, do it deniable
	--link			link (your) --persona as default src to this
				target id
	--newdhp		create new DHparams for persona (rarely needed)
	--brainkey1/2		use secret to derive deniable persona keys
	--salt1/2		optional: use salt when when using brainkeys
	--calgo,	-C	use this algo for encryption
	--phash,	-p	use this hash algo for hashing personas
	--in,		-i	input file (stdin)
	--out,		-o	output file (stdout)
	--name,		-n	use this name for newly created personas
	--burn			(!dangerous!) burn private (EC)DH key after
				decryption to achieve 'full' PFS
```

If you want to use additional features, such as from `opmux` (opmsg/gpg auto forward) or `opcoin`
(using bitcoin network as a web-of-trust), also type `make contrib`. Contrib tools are
documented in README2.md. You may also want to check
[opmsg-qr](https://github.com/stealth/opmsg-qr) later on, to im/export `opmsg`
personas via QR codes, once you have set up your working environment.

Personas
--------

The key concept of _opmsg_ is the use of personas. Personas are
an identity with either an EC or RSA key bound to it. Communication happens between
two personas (which could be the same) which are uniquely identified
by the hashsum of their EC/RSA keys:

```
$ opmsg --newp --name stealth

opmsg: version=1.2 -- (C) 2015 opmsg-team: https://github.com/stealth/opmsg

opmsg: creating new persona

.......[...].........................o..o..o..o..o..oO

opmsg: Successfully generated persona (RSA + DHparams) with id
opmsg: 1cb7992f96663853 1d33e59e83cd0542 95fb8016e5d9e35f b409630694571aba
opmsg: Tell your remote peer to add the following RSA pubkey like this:
opmsg: opmsg --import --phash sha256 --name stealth

-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4Xds/bPlkdqA9VhDBOIEV/Dc9
4EfL5aPBOQAdTIaZKE69SJdwakFhqOY1PeaeGRDcGTVNLBQ1Udgbc2YCgQh1X5Dn
veRIGJoGfqWC7zeq/mx6yRer3PTUOA0gr30Uu7IO128fVDxNLYYUuvzhzcdysZAa
WkmRflKuaCEMQ3RjcQIDAQAB
-----END PUBLIC KEY-----

opmsg: Check (by phone, otr, twitter, id-selfie etc.) that above id matches
opmsg: the import message from your peer.
opmsg: AFTER THAT, you can go ahead, safely exchanging op-messages.

opmsg: SUCCESS.
```

This is pretty self-explaining. A new persona with name `stealth` is
created. The public RSA key of this persona has to be imported by
the remote peer that you want to opmsg-mail with via

```
opmsg --import --phash sha256 --name stealth
```

just as hinted above. After pasting the public key of your communication peer
into above commandline - once it told you to do so - you will be given the persona ID,
that consists of the hashsum (sha256 in this case) of the public key. ID's
may be presented to you in `--short`, `--long`, or `--split` (default) form,
and will be auto-detected in either form as you pass it to the command line.


_opmsg_ does not rely on a web-of-trust which in fact never really
worked. Rather, due to ubiquious messenging, its much simpler today
to verify the hashsum of the persona via **additional** communication
paths. E.g. if you send the pubkey via plain mail, use SMS **and** twitter
to distribute the hash, or send a picture/selfie with the hash
and something that uniquely identifies you. Using **two additional**
communication paths, which are unrelated to the path that
you sent the key along, you have a high degree of trust.
_Side-note: If you want to stay anonymous, do not send selfies
with your persona id and dont use communication paths that can
be mapped to you._

By default `sha256` is used to hash the pubkey blob but you may also specify `ripemd160`
or `sha512`. Whichever you choose, its important that your peer knows
about it during import, because you will be referenced with this hex hash value
(your persona ID) in future.

The private part of the keys which are stored inside `~/.opmsg`
are NOT encrypted. It is believed that once someone gained access
to your account, its all lost anyway (except for PFS as explained later),
so a passpharse just add a wrong feeling of security here. Keep
your account/box unpwned! Otherwise end2end encryption makes little
sense.

_opmsg_ encourages users for easy persona creation and throwaway.
The directory structure below `~/.opmsg` is easy and straight
forward. It just maps the hex ids of the personas and (EC)DH keys
to directories and can in fact be edited by hand.

Creation of RSA personas might take some time. Not just an RSA key
is generated in that case - which is not very time consuming - but also DH
parameters (2048bit by default) that are used to implement PFS
in later messenging (see later chapter).

In order to speed up persona generation and to encourage use- and throwaway
and per-project personas, EC support was added to _opmsg_ as of `version=1.5`.
Instead of `--newp` you would just use `--newecp` and everything else is the
same. `opmsg` will pick the right crypto transparently to you. No need to add
any further switches for encryption or alike. EC personas use the brainpool curves
(RFC 5639). The NIST curve `secp521r1` may also be used as a fallback if your
libcrypto is outdated, but its recommended to use the brainpool curves which
dont keep any secrets about how their group parameters were selected.
Also see the chapter about cross-domain ECDH down below.


Persona linking
---------------

Although this step is not strictly necessary, **it is recommended**. As personas are easily
created, you can (should) create a dedicated persona for each of your "projects" or
contacts. That is, if you have 7 communication partners/peers, you should have
created 7 personas; one EC/RSA key for each of them. To handle that easily with your
mailer (see later for MUA integration), you should add a proper `--name`, describing your
id. If you are using email addresses along with names, use the format of `--name 'da name <name@address>'`
so that your MUA can easily pick a list of candidates for you.

Additionally, you should `--link` your source persona (each of the 7 you created)
to the particular destination persona that you wish to communicate with using this source id:

```
$ opmsg --link b3c32d47dc8b58a6 --persona 1cb7992f96663853

opmsg: version=1.2 -- (C) 2015 opmsg-team: https://github.com/stealth/opmsg

opmsg: linking personas
opmsg: SUCCESS.

```

This is to avoid the need to specify `--persona` each time you
send a message to a different target persona, changing your local
id back and forth inside the config file or at the command line.
Above command says, that each time you send an opmsg to `b3c32d47dc8b58a6`,
the keying material from your local id `1cb7992f96663853` is used. To unlink
your id from `b3c32d47dc8b58a6`, remove the `srclink` file inside this personas
directory.

If no link is found for a persona, the config file and given
`--persona` argument is evaluated. Command line arguments override the config file settings.

Given proper mail provider support (e.g. inboxes are created on the fly
for addresses like hexid@example.com), the global surveillance meta graph would
just contain pairs of communication partners. No clusters, just islands
of 1:1 mappings.


Deniable personas
-----------------

There may be valid scenarios where you dont want your communication peer to have a way to proof
that you wrote a certain message. Since op messages are always signed with your persona
key, peer could proof that you were expressing illegal thoughts. So you want deniable messages
that are still integrity protected. The OTR protocol is handling this by sharing the public as
well as the private key for a dedicated communication session between both peers.

_opmsg_ allows to do the same. It requires an additional communication step with a peer
that you already imported once and which you suspect to do such back stabbing.
(Generally speaking its wise to assume that case.)

It is recommended to use EC personas for that purpose, as its faster. Just add `--deniable`
switch on the commandline when creating or importing this deniable persona as well
as a `--name` that reflects deniability for you.
This will print or import the private key half of the persona and link it to itself.

As this new persona is linked to itself, whenever you send something to the peer the
signing key is shared with _that_ peer. You can always deny that you sent this message
as your peer could also have signed it (`src-id` and `dst-id` inside the message are the same).
**Only exchange deniable persona keys across an existing secure (encrypted) channel as it
contains private keying material.
Do not share any key material of this dedicated new EC persona to anyone else. Its only for
this dedicated, deniable, communication peer.**

Once a deniable peer is established, you may use it as often and as long as you wish
and as within normal operation.
Deniable op messages are integrity protected and feature all crypto benefits.

Of course for this to work you also want to have fully encrypted your disk to leave no
forensic artifacts and dont want to cite your peer in reply-messages as this proofs
that you were able to decrypt a mail from your peer, e.g. you are hold of a certain
private session key (`kex-id`). Thats a common mistake people make who dont sign
their emails and think everything is deniable.


Brainkey Personas
-----------------

Brainkey personas are deniable personas whose key was not generated via RNG
input, but which are derived from a passphrase. They are very similar to the
concept of BTC brainwallets. When generating brainkey personas, the commandline
should be as explicit as possible in order to have matching personas on both sides
despite potentially different config-file settings for EC curves or hash algos:

```
$ opmsg --name=nobrainer --deniable --salt1 1234 --brainkey1 --newecp=secp521r1 --phash=sha256

opmsg: version=1.80 (C) 2021 Sebastian Krahmer: https://github.com/stealth/opmsg

opmsg: Enter the brainkey, 16 chars minimum (echoed): mysupersecretnobodyknows
opmsg: creating new EC persona (curve secp521r1)



opmsg: Successfully generated persona with id
opmsg: a6da74f688c375d8 96858709ffd1a25f d42e6523bb89d0f2 45cfe554cf7b4e7c
opmsg: You created a deniable persona.
opmsg: Your persona key was derived from a brainkey. No need to exchange keys
opmsg: with your peer. Your peer just needs to execute the same command as you
opmsg: in order to create the same deniable persona on their side.

opmsg: SUCCESS.
```

Ofcorse, you should use a secret that nobody can guess or bruteforce, including
upper and lower-case, digits and so on. The idea behind brainkey personas is,
that you share a secret with your peer once you meet, and both sides can
then generate the same personas independently afterwards. There's no need to verify
finger prints or exchange keys. The salt parameter doesn't need to be secret and may
also be omitted. But it is a safety measure to chose a salt in order to make attacks
with rainbow tables unfeasable. If you are certain that no other users
are on your box, you may also pass the passphrase as `--brainkey1=mysupersecretnobodyknows`
on the commandline instead of typing it on `stdin`.
Brainkeys will only be used for deniable EC personas. The Kex (aka Session) keys
will nevertheless be generated randomly, just as for other personas.
Brainkey personas can then be used just as normal. Once created, you may just
forget the brainkey, as you will never need to generate it again.


Post-Quantum Personas
---------------------

As of `version=4` messages, *opmsg* supports personas who resist quantum computing power.
These personas have type `pq1` in the `opmsg -l` listing and are basically brainkey
personas as above but include a symmetric salt thats used together with the ECDH Kex
to derive the session key. The integrity of `version=4` (and above) messages is not only
protected by asymmetric signatures (RSA or ECC) but by also extending the AAD of AES-GCM to
the entire header, including exchanged keys and the Kex part. This ensures that even
with quantum computing power, an adversary cannot modify the message or break the session
keys. PQC-Personas are generated similar to `brainkey1` personas:

```
$ opmsg --name=quantum-tarantino --deniable --salt2 1234 --brainkey2 --newecp=secp521r1 --phash=sha256
[...]
```

I.e. by using `--brainkey2` instead of `--brainkey1`.
For `pq1` personas, *opmsg* only accepts `aes256gcm` and `chacha20-poly1305` cipher algos,
in order to fully protect the entire message with AAD as described above.
This symmetric salt solution is recommended by the BSI (Federal Office of Information
Security in good old Germany) durin the transitioning phase. Note, that neither *OpenSSL*
supports PQC yet, nor are there any standartized algorithms, nor recommend any of the PQC
projects to use their code in production, so having this transitioning solution is the most
portable way of adding PQC to *opmsg*.


Message Encryption
------------------

In order to encrypt messages, you have to specify the persona ID of the recipient:

```
$ opmsg -E 12344d8921323601 --out msg1.opmsg
...
```

If no `--in` parameter is given, the message is read from `stdin` until `Ctrl-C`.
The fastest way is to use the long form of the persona ID, but its also the most
inconvenient form. Above example uses the short ID of the target persona. It already
requires some searching inside the keystore for that particluar ID, but its still fast.
The most convenient, but slowest form allows to use names as recipient. It requires to
search the entire keybase until a name-match is found. Note, that this is potentially
ambigious and you must not have more than one persona with the same name field in your
keystore:

```
$ opmsg --name friend@localhost -E name --in msg2 --out msg2.opmsg
...
```

`-E name` refers to use names instead of IDs. Still, it is recommended to use the hex-id as
recipient, since its the more bullet-proof approach.


Keys
----

Now for the coolest feature of _opmsg_: Perfect Forward Secrecy (PFS).

Without any need to re-code your mail clients or add bloat to the
SMTP protocol, _opmsg_ supports PFS by means of (EC)DH Kex out of the box.

For RSA personas, DH Kex is used. For EC personas ECDH Kex is used to derive
the secret, hence the term (EC)DH.

As op-messages are _always_ signed by its source persona,
whenever you send an opmsg to some other persona, a couple of
(EC)DH keys are generated and attached to the message. The remote
_opmsg_ will verify its integrity (as it has this persona imported)
and add it to this persona's keystore. So whenever this remote peer
sends you a mail next time, it can choose one of the (EC)DH keys it has
got beforehand. If your peer runs out of (EC)DH keys, _opmsg_ falls
back to native RSA or EC encryption, depending of the type of persona.
The peer deletes used (EC)DH pubkeys to not
use them twice and the local peer marks used keys with a
`used` file within the apropriate key-directory. Once again,
`sha256` is used by default to index and to (worldwide) uniquely
identify (EC)DH keys.

**Attention:** If you keep encrypted op-messages in your mailbox,
do not throw away this persona. You wont be able to decrypt these mails
afterwards! Throwing away a persona also means to throw away all keying
material. Thats why _opmsg_ has no switch to erase personas. You have
to do it by hand, by rm-ing the subdirectory of your choice. Thats
easily done, but keep in mind that any dangling op-messages in your
inbox will become unreadable, as all keys will be lost. If you want to
benefit from PFS, you have to archive the **decrypted** messages and
throw away `used` keys. After all _opmsg_ is not a crypto container
or a replacement for FDE (which is recommended anyway). _opmsg_ is
about to protect your messages in transit, not on disk.

As of `version=1.3` there is a `--burn` option that nukes used DH
keys from storage. Be aware: you can only decrypt the message once.
Once the message is successfully decrypted, the (EC)DH key that was used
is overwritten and deleted from storage.


cross-domain ECDH
-----------------

You may skip this section if you are not really paranoid about potentially
backdoored EC curves and how to cope with it.

There is a (yet experimental) feature, which may be enabled by using protocol version 3
and specifying more than one EC curve in the config:


```
...
version=3
...
curve=brainpoolP384r1
curve=secp256k1
...
```

Up to three different curves may be specified. For each curve specified, a dedicated ECDH
handshake is made. That is, the key used for encrypting the message is derived from more
than one ECDH Kex. The 'common' ECDH handshake, as seen in all other protocols like TLS etc.,
uses one curve. _opmsg_ by default also uses one curve. But you can use more than one, and
here is why: There is an endless discussion about which curve can be trusted. Some prefer
the NIST curves, some prefer Brainpool and some prefer even other curves. As shown in
various papers, it is possible by evil EC-curve designers to choose the curve domain parameters
in a way that places backdoors into the curve. That is, by knowing certain seeding parameters,
it is possible to create legit looking curves which fullfil all requirements, yet producing
weak secrets, if the attacker knows the evil seeding bits. It is not just a theroretical issue
that evil committee members place backdoors into standards (take the dual-EC-DRBG as a warning).

The idea behind cross-domain ECDH is that, even if we assume all EC curves to contain
backdoored parameters, the knowledge about it is so well protected that it is not shared
across each other. Would the NIST share their backdoor seedings with the russians or vice versa?
Certainly they wouldn't.
In other words, each backdooring party would keep their evil seeding
for themselfs. By using cross-domain ECDH, we exploit this fact and can negotiate a strong secret,
even with potentially backdoored EC curves.

This is for the negotiated session keys. The persona keys (used for signing) are still generated using a single curve.
But you may use cross-doamin ECDH with RSA personas now, by specifying

```
...
ecdh-rsa
...
```

in the config.


MUA integration
---------------

First, add to your _~/.gnupg/options_ file the following line:

```
keyid-format long
```

Next, there are two possible ways to integrate _opmsg_ into your MUA. For cool
MUAs like __mutt__, you may build a dedicated _.muttrc_ by adding:

```
# Add a header so to easy pick opmsg via procmail rules
my_hdr X-opmsg: version1

set pgp_long_ids

# use this listing mode if the 'name' aliases are a substring of the email address
# to avoid huge listings
set pgp_list_pubring_command="/usr/local/bin/opmsg --listpgp --short --name %r"

# otherwise, skip the --name option to list all personas
#set pgp_list_pubring_command="/usr/local/bin/opmsg --listpgp --short"

set pgp_encrypt_sign_command="/usr/local/bin/opmsg --encrypt '%r' -i %f"
set pgp_encrypt_only_command="/usr/local/bin/opmsg --encrypt '%r' -i %f"
set pgp_decrypt_command="/usr/local/bin/opmsg --decrypt -i %f"
set pgp_verify_command="/usr/local/bin/opmsg --decrypt -i %f"

# or set to "^opmsg: SUCCESS\.$" - only required for newer mutt versions
#unset pgp_decryption_okay

```

and work with your mails as you would it with _PGP/GPG_ before. If you
use a mix of _GPG_ and _opmsg_ peers, its probably wise to create
a dedicated _.muttrc_ file for _opmsg_ and route _opmsg_ mails to
a different inbox, so you can easily work with GPG and _opmsg_ in
parallel. Note that some mutt installs (neomutt) require the `-n` switch
if you load your own config via `-F` in order to skip processing of system-wide
config files. This would otherwise overload all of your pgp variables.

But theres also another option: Using _opmux_:

```
set pgp_long_ids

# OPMUX_MUA env setting is optional and only required if you use 'pgp_decryption_okay' in newer mutts

set pgp_decode_command="OPMUX_MUA=mutt /usr/local/bin/opmux --passphrase-fd 0 --quiet --batch --output - %f"
set pgp_verify_command="OPMUX_MUA=mutt /usr/local/bin/opmux --quiet --batch --output - --verify %s %f"
set pgp_decrypt_command="OPMUX_MUA=mutt /usr/local/bin/opmux --passphrase-fd 0 --quiet --batch --output - %f"

set pgp_encrypt_only_command="/usr/local/bin/opmux --batch --quiet --output - --encrypt \
                              --textmode --armor --always-trust -r '%r' %f"
set pgp_encrypt_sign_command="/usr/local/bin/opmux --passphrase-fd 0 --batch --quiet --textmode \
                  --output - --encrypt --sign %?a?-u %a? --armor --always-trust -r '%r' %f"

set pgp_list_pubring_command="/usr/local/bin/opmux --batch --quiet --with-colons --list-keys %r"

# Be sure to not override it later on. This regex may also be unset.
set pgp_decryption_okay="^opmux: SUCCESS\.$"

```

_opmux_ is a wrapper for _opmsg_ and _gpg_, which transparently forwards encryption and decryption
requests to the right program, by checking message markers and persona ids.
This way you may use your _opmsg_ and _gpg_ setup in parallel and the correct (de)crypt program is
automagically invoked. When you send a Mail and an _opmsg_ persona is found for the destination,
_opmsg_ is used for encryption, otherwise _gpg_ is used.
This requires your personas to be properly `--link`ed or having a valid `my_id` in your
_opmsg_ config.

For __enigmail__ or other MUAs you would just configure the gpg-path to be `/path/to/opmux` and you
are done (but dont forget the `keyid-format long` from the first step).

_opmux_ prefers the _gpg2_ over the _gpg_ binary if both gpg versions are installed. If you
have both gpg versions installed in parallel but for whatever reason want to work with your (old) gpg1 keys,
you have to change the call order in `opmux.c` _gpg()_ function.

All this however is just for convenience. The more GUI and layering you add to your
_opmsg_ setup, the more chance you have to use wrong destination or source personas. So
be sure to thoroughly test your setup. Again, make sure your personas are properly linked
and you have a clean default persona id assigned in the config.

Cc and Bcc
----------

Since `version=1.65` opmsg supports Cc/Bcc from mails, e.g. you may specify more than
one `-E` persona recipient. However if you used to Cc messages to yourself for
archiving, you must not use `--burn` because in fact you are referencing session
keys that were initially generated for someone else. Then at times when this peer
send you encrypted messages, you will miss that key.

Please note that in general using crypted mails and Cc is leaking privacy, as
the destination personas see whats in your keystore and which key ids you are
referencing. Its also asking for headache if you did not set up your keystore properly
(linking personas and keeping the link ids up to date, removing dead personas etc.)

If you are operating, you may also consider a dedicated account (machine) with a dedicated opmsg
setup so that you dont accidently sign operational messages with source personas that
link to a publically known profile. Deniable messages wont help in that case.

Config file
-----------

You need to setp up your local `~/.opmsg/config` to reflect
the source persona you are using when sending your mail via _mutt_,
unless you specify it via `-P` on the commandline or used `--link`:
(linking personas is recommended, see above)


```
# opmsg sample config

# 1 or 2. Default is 2. The KDF in version=2 is hardened against evil maid attacks.
# Only use version=2 if you know your peer uses opmsg >= 1.60 that can handle version=2.
# Your peer then automatically chooses right version. Theres no config change needed
# for your peer.
version=2

# Using the long format optimizes keystore loading, as an exact lookup takes place,
# and  searching the keystore is avoided.
# Also see 'linking personas' in README. It is recommended to use different ID
# for each communication peer.
my_id = 50973f3cfc3e0f3f1a7d4047aa6fa7645510f3b4ddc486a4b72bcacdf3aad570

# default
rsa_len = 4096

# default
dh_plen = 2048

calgo = aes128ctr

# the ID output format (default)
idformat = split

new_dh_keys = 3

# EC curve to be used for EC personas (prefered since its faster)
# Default. Other choices: secp521r1 (be aware: NIST curve!), brainpoolP320t1, brainpoolP384r1,
# brainpoolP384t1, brainpoolP512r1, brainpoolP512t1
curve = brainpoolP320r1

# Check on decrypt whether the sender (src-id) used a kex-id that was once sent to him
# as a dst-id.
# This allows you detect cross-references for people using different src personas to
# to contact a single persona of yours. This way you can detect/enforce isolation.
# By default its disabled.
peer_isolation=1

```

Supported ciphers
-----------------

```
$ opmsg -C inv -D

opmsg: version=1.64 -- (C) 2015 opmsg-team: https://github.com/stealth/opmsg

opmsg: Invalid crypto algorithm. Valid crypto algorithms are:

opmsg: aes128cbc (default)
opmsg: aes128cfb
opmsg: aes128ctr
opmsg: aes128gcm
opmsg: aes256cbc
opmsg: aes256cfb
opmsg: aes256ctr
opmsg: aes256gcm
opmsg: bfcbc
opmsg: bfcfb
opmsg: cast5cbc
opmsg: cast5cfb
opmsg: null

opmsg: FAILED.
```

Examples
--------

```
$ opmsg --list --short

opmsg: version=1.2 -- (C) 2015 opmsg-team: https://github.com/stealth/opmsg

opmsg: persona list:
opmsg: Successfully loaded 1 personas.
opmsg: (id)     (name)  (has-RSA-priv)  (#DHkeys)
opmsg: 1cb7992f96663853 stealth 1       0
opmsg: SUCCESS.
```
Creating a detached signature for a file:
```
$ echo foo>foo
$ opmsg --sign -i foo --persona 1cb7992f96663853|tee -a foo.sign

opmsg: version=1.2 -- (C) 2015 opmsg-team: https://github.com/stealth/opmsg

opmsg: detached file-signing by persona 1cb7992f96663853
opmsg: SUCCESS.
-----BEGIN OPMSG-----
version=1
-----BEGIN SIGNATURE-----
U822A12k1IZiWqRKAr6uLKT/7HGR4inKpkqzz49xLNjBf4mo91HUxcPMFGQTDB/MbE9HqtdCgHNexfIy
GCC6Jb6egt2D70nIyhWfksW9KljdqwQzUbXp9CubxRAz5EqTS0n0ze092LuXxV4SuKV628CTBr5siIcf
za6g3Sfh+vg=
-----END SIGNATURE-----
rythmz=sha256:sha256:sha256:null:DOauqyrqoH4zslO4gr3FFI7EMbcLtRzU
src-id=1cb7992f966638531d33e59e83cd054295fb8016e5d9e35fb409630694571aba
dst-id=1cb7992f966638531d33e59e83cd054295fb8016e5d9e35fb409630694571aba
kex-id=00000000
-----BEGIN OPMSG DATA-----
b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c
-----END OPMSG-----
```
Verifying it:
```
$ sha256sum foo
b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c  foo
$ opmsg -V foo -i foo.sign

opmsg: version=1.2 -- (C) 2015 opmsg-team: https://github.com/stealth/opmsg

opmsg: verifying detached file
opmsg: GOOD signature and hash via persona 1cb7992f96663853 1d33e59e83cd0542 95fb8016e5d9e35f b409630694571aba
opmsg: SUCCESS.
$ opmsg -V foo -i foo.sign --short

opmsg: version=1.2 -- (C) 2015 opmsg-team: https://github.com/stealth/opmsg

opmsg: verifying detached file
opmsg: GOOD signature and hash via persona 1cb7992f96663853
opmsg: SUCCESS.
```

Meta data
---------

If you care about meta data collection and want to reduce your data-tracks
even further, check out [drops](https://github.com/stealth/drops).
_drops_ is a p2p transport network for _opmsg_. It allows you to anonymously
drop end2end encrypted op-messages without leaking meta-data such as mail headers.

