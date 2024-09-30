# DPIS
```
      :::::::::  ::::::::: ::::::::::: ::::::::
     :+:    :+: :+:    :+:    :+:    :+:    :+:
    +:+    +:+ +:+    +:+    +:+    +:+         mitm
   +#+    +:+ +#++:++#+     +#+    +#++:++#++
  +#+    +#+ +#+           +#+           +#+
 #+#    #+# #+#           #+#    #+#    #+#   by N0x4z3r, Rmalet
#########  ###       ########### ########    (called Deep-Peace)
```

<i>Dynamic Protocols Injection and Spoofing</i>

#### <u>__Description:__</u>

#### <u>__Requirements:__</u>
```list
- Python 3.9+
- Python3-pip
- libpcap or npcap for Windows
```

### Summary
```
The goal of the project is prepare the maximum of the setups for starting MITM attack.
That permit enhance speed in case of intercepting/injection inside batch of requests,
we started with MySQL protocol due to the nature of our CTF,
but we build it to implement others protocols.

In first, we look on the Layer 2 to get original values of the hosts on the network,
after then we start to create a arp poisonning attack,
this permit to redirect packet to the attacker machine.
After, we can do setups for our Layer 3 attack, packet forgery for IP layer,
and detect incoming connection with a valid source port.

At this moment, there is multiple possibilities to achieve our goals:
	- Artificially increment the sequence, to deSYNchronise the client.
	- Inject on client side a false packet with a Login error.
	- Inject on server side our malicious request to get our the required data (credential by example),
		or set a custom credential to obtain privileges on the target.
	- Last possibility is to craft a packet by impersonating the victim,
		but this way pretend the privileges are held by being a host, not by credentials,
		so in most of cases this is not a valuable way to achieve our goal but
		at least a part of the complete attack.
```