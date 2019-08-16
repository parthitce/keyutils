#!/bin/bash

. ../../../prepare.inc.sh
. ../../../toolbox.inc.sh


# ---- do the actual testing ----

result=PASS
echo "++++ BEGINNING TEST" >$OUTPUTFILE

# check standard IDs
marker "CHECK STD IDS"
id_key --fail @t
expect_error ENOKEY
id_key --fail @p
expect_error ENOKEY
id_key @s
id_key @u
id_key @us
id_key --fail @g
expect_error EINVAL
id_key --fail @a
expect_error ENOKEY

# create a keyring
marker "CREATE KEYRING"
create_keyring lizard @s
expect_keyid keyid

# check that a non-keyring ID works
marker "CHECK NON-KEYRING KEY"
id_key $keyid
id_key %:lizard
id_key --fail %:lizardx

# dispose of the key we were using
marker "UNLINK KEYRING"
unlink_key --wait $keyid @s

# check that a non-existent key ID fails correctly
marker "CHECK NON-EXISTENT KEYRING ID"
id_key --fail $keyid
expect_error ENOKEY

# create a non-keyring
marker "CREATE KEY"
create_key user lizard gizzard @s
expect_keyid keyid

# check that a non-keyring ID works
marker "CHECK NON-KEYRING KEY"
id_key $keyid
id_key %user:lizard

# dispose of the key we were using
marker "UNLINK KEY"
unlink_key --wait $keyid @s

# check that a non-existent key ID fails correctly
marker "CHECK NON-EXISTENT KEY ID"
id_key --fail $keyid
expect_error ENOKEY

echo "++++ FINISHED TEST: $result" >>$OUTPUTFILE

# --- then report the results in the database ---
toolbox_report_result $TEST $result
