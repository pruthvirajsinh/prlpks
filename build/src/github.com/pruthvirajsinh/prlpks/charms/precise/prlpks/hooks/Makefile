
all: peer-relations gossip-relations cluster-relations

peer-relations: peer-relation-joined peer-relation-broken peer-relation-changed peer-relation-departed

gossip-relations: gossip-relation-joined gossip-relation-broken gossip-relation-changed gossip-relation-departed

cluster-relations: cluster-relation-joined cluster-relation-broken cluster-relation-changed cluster-relation-departed

peer-relation-%: recon-relation-changed
	ln -s recon-relation-changed $@

gossip-relation-%: recon-relation-changed
	ln -s recon-relation-changed $@

cluster-relation-%: recon-relation-changed
	ln -s recon-relation-changed $@

clean:
	$(RM) peer-* gossip-* cluster-*

.PHONY: all peer-relations gossip-relations cluster-relations

