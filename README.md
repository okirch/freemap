## FreeMAP

This utility should do few things than nmap does.
Without being nmap.

Right now, it is not doing *anything* useful as I'm in the hack-and-break phase.
In particular, the targets to scan are current hard-coded in main.c :-)

# Building

This needs https://github.com/okirch/libcurlies for handling configuration files.


# Using

Rather than putting the entire scan process into one huge pipeline, freemap tries
to split this up into several stages that can be run independently. The idea is that
you may want to re-run parts of a scan, possibly with different arguments, without
having to watch it go through *all* the necessary paces.

```
  freemap init
```

This will initialize the current directory as a scan project. You can then go on and
configure your scan:

```
  freemap add-targets 192.168.1.0/24
  freemap set reachability-scan magicscan
  freemap set service-scan thorough
```

You can then run the entire scan process at once, as most other scanners will do:

```
  freemap scan
```

Alternatively (and this code is not there yet), you could run individual steps

```
  freemap topology
  freemap hosts
  freemap services
```

A topology scan performs traceroute-like probes to understand which hops lie between
you and a target network; this information can be used in tuning packet rates and
for priming rtt estimates.

The host reachability scan performs various probes to identify hosts which are reachable
at all. Typically, this would be an ICMP ping or an ARP lookup, but other, more
exotic probes are possible as well.

Finally, the services scan will probe whether services are listening on UDP and TCP ports.
