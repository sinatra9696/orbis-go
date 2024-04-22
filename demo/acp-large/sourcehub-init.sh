#!/bin/sh

MONIKER=demo
VALIDATOR1=validator1
VALIDATOR2=validator2
VALIDATOR3=validator3
VALIDATOR4=validator4
VALIDATOR5=validator5
VALIDATOR6=validator6
VALIDATOR7=validator7
ALICE=alice
BOB=bob

sourcehubd init $MONIKER --chain-id sourcehub

sourcehubd keys add ${VALIDATOR1} --keyring-backend test
sourcehubd keys add ${VALIDATOR2} --keyring-backend test
sourcehubd keys add ${VALIDATOR3} --keyring-backend test
sourcehubd keys add ${VALIDATOR4} --keyring-backend test
sourcehubd keys add ${VALIDATOR5} --keyring-backend test
sourcehubd keys add ${VALIDATOR6} --keyring-backend test
sourcehubd keys add ${VALIDATOR7} --keyring-backend test

# Static keys for testing
# Alice Address source16dgy2uw5p74a0pzuwmq0hpl44xzn2yfauxfc70
# private Key: puNSnlhhQVzhxcST+EjI+kln+tKIh0tRct29BY9mgQ4=
# public Key: Ay181c7HWcRib08KMzYNRLqN3kwTFhsfSScAScSX6uDs

# Bob Address source1c30ctscyfhudwpaw3jdfjnc6vhzeqygjwt39zy
# private Key: U7UHuJYs+xF7fACCsKrthBb6nMQ0MA+IpRiD2Xza78o=
# public Key: ArndsH/I2tiTRAgvhT8yU5YMwpZnt3EKy6VtIdF8nXqJ
cat /demo/alice.seed | sourcehubd keys add ${ALICE} --recover --keyring-backend test
cat /demo/bob.seed | sourcehubd keys add ${BOB} --recover --keyring-backend test

VALIDATOR1_ADDRESS=$(sourcehubd keys show ${VALIDATOR1} --address --keyring-backend test)
VALIDATOR2_ADDRESS=$(sourcehubd keys show ${VALIDATOR2} --address --keyring-backend test)
VALIDATOR3_ADDRESS=$(sourcehubd keys show ${VALIDATOR3} --address --keyring-backend test)
VALIDATOR4_ADDRESS=$(sourcehubd keys show ${VALIDATOR4} --address --keyring-backend test)
VALIDATOR5_ADDRESS=$(sourcehubd keys show ${VALIDATOR5} --address --keyring-backend test)
VALIDATOR6_ADDRESS=$(sourcehubd keys show ${VALIDATOR6} --address --keyring-backend test)
VALIDATOR7_ADDRESS=$(sourcehubd keys show ${VALIDATOR7} --address --keyring-backend test)

ALICE_ADDRESS=$(sourcehubd keys show ${ALICE} --address --keyring-backend test)
BOB_ADDRESS=$(sourcehubd keys show ${BOB} --address --keyring-backend test)

sourcehubd genesis add-genesis-account $VALIDATOR1_ADDRESS 100000000stake

sourcehubd genesis add-genesis-account $VALIDATOR2_ADDRESS 100000stake
sourcehubd genesis add-genesis-account $VALIDATOR3_ADDRESS 100000stake
sourcehubd genesis add-genesis-account $VALIDATOR4_ADDRESS 100000stake
sourcehubd genesis add-genesis-account $VALIDATOR5_ADDRESS 100000stake
sourcehubd genesis add-genesis-account $VALIDATOR6_ADDRESS 100000stake
sourcehubd genesis add-genesis-account $VALIDATOR7_ADDRESS 100000stake

sourcehubd genesis add-genesis-account $ALICE_ADDRESS 100000stake
sourcehubd genesis add-genesis-account $BOB_ADDRESS 100000stake

sourcehubd genesis gentx ${VALIDATOR1} 70000000stake --chain-id sourcehub --keyring-backend test

sourcehubd genesis collect-gentxs

sed -i -e 's/timeout_commit = "5s"/timeout_commit = "1s"/g' /root/.sourcehub/config/config.toml
