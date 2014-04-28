#!/bin/bash -x

juju deploy --repository=. local:precise/prlpks
juju deploy postgresql
juju add-relation prlpks postgresql:db
juju expose prlpks
