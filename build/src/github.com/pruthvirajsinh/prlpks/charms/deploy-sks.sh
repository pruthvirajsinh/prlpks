#!/bin/bash -x

juju deploy --repository=. local:saucy/sks
juju expose sks
