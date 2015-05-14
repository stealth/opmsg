opmsg
=====

A gpg alternative
-----------------

_opmsg_ is a replacement for _gpg_ which can encrypt/sign/verify
your mails or create/verify detached signatures of local files.
Even though the _opmsg_ output looks similar, the concept is entirely
different.

Features:

* Perfect Forward Secrecy (PFS) by means of DH Kex
* RSA fallback if no DH keys left
* fully compliant to existing SMTP/IMAP/POP etc. standards;
  no need to touch any mail daemon/client/agent code
* signing messages is mandatory
* easy creation and throw-away of ids
* support for 1:1 key bindings to auto-select source key per destination
* adds the possibility to (re-)route messages different
  from mail address to defeat meta data collection
* configurable well-established hash and crypto algorithms
  and key lengths (RSA, DH)
* straight forward and open key storage, basically also managable via
  `cat`, `shred -u` and `ls` on the cmdline
* seamless mutt integration

Build
-----

_opmsg_ requires the crypto primitives from _OpenSSL_. Just relax, its
not using the SSL/TLS proto, just the ciphering and hash algorithms.
For standard _Linux_ distros, just type `make`.

The compilation requires a C++ compiler that supports `-std=c++11`.
This can be configured with e.g. `make CXX=eg++ LD=eg++` on _OpenBSD_.

This project supports both `BN_GENCB_new` and `BN_GENCB` for big number
generation. To disable `BN_GENCB_new`, set `HAVE_BN_GENCB_NEW` to false:
`make DEFS=-DHAVE_BN_GENCB_NEW=0`. So on _OpenBSD_, you would run
`make CXX=eg++ LD=eg++ DEFS=-DHAVE_BN_GENCB_NEW=0`. On _OSX_ you should install
your own _OpenSSL_, as Apple marks _OpenSSL_ as deprecated in favor of their own
crypto libs.

```
$ make
[...]
$ cp opmsg /usr/local/bin/
$ opmsg

opmsg: version=1.2 -- (C) 2015 opmsg-team: https://github.com/stealth/opmsg


Usage: opmsg    [--confdir dir] [--rsa] [--encrypt dst-ID] [--decrypt] [--sign]
                [--verify file] <--persona ID> [--import] [--list] [--listpgp]
                [--short] [--long] [--split] [--newp] [--newdhp] [--calgo name]
                [--phash name [--name name] [--in infile] [--out outfile]
                [--link target id]

        --confdir,      -c      defaults to ~/.opmsg
        --rsa,          -R      RSA override (dont use existing DH keys)
        --encrypt,      -E      recipients persona hex id (-i to -o, requires -P)
        --decrypt,      -D      decrypt --in to --out
        --sign,         -S      create detached signature file from -i via -P
        --verify,       -V      verify hash contained in detached file against -i
        --persona,      -P      your persona hex id as used for signing
        --import,       -I      import new persona from --in
        --list,         -l      list all personas
        --listpgp,      -L      list personas in PGP format (for mutt etc.)
        --short                 short view of hex ids
        --long                  long view of hex ids
        --split                 split view of hex ids
        --newp,         -N      create new persona (should add --name)
        --link                  link (your) --persona as default src to this target id
        --newdhp                create new DHparams for a given -P (rarely needed)
        --calgo,        -C      use this algo for encryption
        --phash,        -p      use this hash algo for hashing personas
        --in,           -i      input file (stdin)
        --out,          -o      output file (stdout)
        --name,         -n      use this name for newly created personas

```

It successfully builds on _Linux_, _OSX_, _OpenBSD_ and probably a lot of others
(_Solaris_, _FreeBSD_,...).

Personas
--------

The key concept of _opmsg_ is the use of personas. Personas are
an identity with a RSA key bound to it. Communication happens between
two personas (which could be the same) which are uniquely identified
by the hashsum of their RSA keys:

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

just as hinted above.

_opmsg_ does not rely on a web-of-trust which in fact never really
worked. Rather, due to ubicious messenging, its much simpler today
to verify the hashsum of the persona via **additional** communication
paths. E.g. if you send the pubkey via plain mail, use SMS **and** twitter
to distribute the hash, or send a picture/selfie with the hash
and something that uniquely identifies you. Using **two additional**
communication paths, which are unrelated to the path that
you sent the key along, you have a high degree of trust.
_Side-note: If you want to stay anonymous, do not send selfies
with your persona id and dont use communication paths that can
be mapped to you._

By default `sha256` is used to hash the RSA keyblob but you may also specify `ripemd160`
or `sha512`. Whichever you choose, its important that your peer knows
about it during import, because you will be referenced with this hex hash value
in future.

The private part of the keys which are stored inside `~/.opmsg`
are NOT encrypted. It is believed that once someone gained access
to your account, its all lost anyway (except for PFS as explained later),
so a passpharse just add a wrong feeling of security here. Keep
your account/box unpwned! Otherwise end2end encryption makes little
sense.

_opmsg_ encourages users for easy persona creation and throwaway.
The directory structure below `~/.opmsg` is easy and straight
forward. It just maps the hex ids of the personas and DH keys
to directories and can in fact be edited by hand.

Creation of personas might take some time. Not just an RSA key
is generated - which is not very time consuming - but also DH
parameters (1024bit by default) that are used to implement PFS
in later messenging (see later chapter).

**Note:** *opmsg*s printing versions earlier than `opmsg: version=1.2` have had a weakness
that left the personas RSA's (public) **e** value integrity-unprotected during `--import`.
This could lallow attackers to mount MiM attacks that
downgrade **e** to 1. Its recommended to update to the newest version, which
correctly hashes the whole RSA pubkey and detects such tampering during `--import`. It is unlikely that such
an attack goes unnoticed, as wrong message signatures would most likely be detected
during operation, but if in doubt you can use the `rsa-check` script to check
your local keystore to not contain any Exponent values of 1. In either case, update
your *opmsg* to be on the safe side. As a bonus you would also get the new and
shiny *aes-gcm* and *aes-ctr* cipher modes!


Persona linking
---------------

Although this step is not strictly necessary, it is recommended. As personas are easily
created, you can (should) create a dedicated persona for each of your "projects" or
contacts. That is, if you have 7350 communication partners/peers, you should have
created 7350 personas; one RSA key for each of them. To handle that easily with your
mailer (see later for mutt integration), you should add a proper `--name`, describing your
id. Additionally, you should `--link` your source persona (each of the 7350 you created)
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
`--persona` argument is evaluated. Command line arguments
override the config file settings.

Given proper mail provider support (e.g. inboxes are created on the fly
for addresses like hexid@example.com), the global surveillance meta graph would
just contain pairs of communication partners. No clusters, just islands
of 1:1 mappings.


Keys
----

Now for the coolest feature of _opmsg_: Perfect Forward Secrecy (PFS).

Without any need to re-code your mail clients or add bloat to the
SMTP protocol, _opmsg_ supports PFS by means of DH Kex out of the box.

That is, as op-messages are _always_ signed by its source persona,
whenever you send an opmsg to some other persona, a couple of
DH keys are generated and attached to the message. The remote
_opmsg_ will verify its integrity (as it has this persona imported)
and add it to this persona's keystore. So whenever this remote peer
sends you a mail next time, it can choose one of the DH keys it has
got beforehand. If your peer runs out of DH keys, _opmsg_ falls
back to RSA encryption. The peer deletes used DH pubkeys to not
use them twice and the local peer marks used keys with a
`used` file within the apropriate key-directory. Once again,
`sha256` is used by default to index and to (worldwide) uniquely
identify DH keys.

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



mutt integration
----------------

Just add to your _.muttrc_:

```
# Add a header so to easy pick opmsg via procmail rules
my_hdr X-opmsg: version1

set pgp_long_ids

set pgp_list_pubring_command="/usr/local/bin/opmsg --listpgp --short --name %r"
set pgp_encrypt_sign_command="/usr/local/bin/opmsg --encrypt %r -i %f"
set pgp_encrypt_only_command="/usr/local/bin/opmsg --encrypt %r -i %f"
set pgp_decrypt_command="/usr/local/bin/opmsg --decrypt -i %f"
set pgp_verify_command="/usr/local/bin/opmsg --decrypt -i %f"
```

and work with your mails as you would it with _PGP/GPG_ before. If you
use a mix of _GPG_ and _opmsg_ peers, its probably wise to create
a dedicated _.muttrc_ file for _opmsg_ and route _opmsg_ mails to
a different inbox, so you can easily work with GPG and _opmsg_ in
parallel.

Config file
-----------

You need to setp up your local `~/.opmsg/config` to reflect
the source persona you are using when sending your mail via _mutt_,
unless you specify it via `-P` on the commandline or used `--link`:


```
# Should use long format to avoid loading of whole keystore.
# this is above generated persona so it owns the RSA private key
my_id = 1cb7992f966638531d33e59e83cd054295fb8016e5d9e35fb409630694571aba

# default
rsa_len = 4096

# default
dh_plen = 1024

calgo = aes128ctr
```

However, any option could also be passed as a commandline argument to
_opmsg_.

Supported ciphers
-----------------

```
$ opmsg -C inv -D

opmsg: version=1.2 -- (C) 2015 opmsg-team: https://github.com/stealth/opmsg

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

As _opmsg_ adds additional ids to the mail, it is possible to send all
mail to random address of the destination persona provider who then
could route it to the real mailbox or even offer everything as a single
blob to download for everyone.
This may be useful to defeat mail meta data collection. op-messages are
self contained and ASCII-armored, so they could also be pasted to OTR,
newsgroups, chats or paste-sites and picked up by the target persona from within
a swarm. Also see above discussion of persona linking.


