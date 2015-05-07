opmsg
=====


```
set pgp_long_ids

set pgp_list_pubring_command="/usr/local/bin/opmsg --listpgp --short"
set pgp_encrypt_sign_command="/usr/local/bin/opmsg --encrypt %r -i %f"
set pgp_encrypt_only_command="/usr/local/bin/opmsg --encrypt %r -i %f"
set pgp_decrypt_command="/usr/local/bin/opmsg --decrypt -i %f"
set pgp_verify_command="/usr/local/bin/opmsg --decrypt -i %f"
```

