## FreeMAP

This utility should do few things than nmap does.
Without being nmap.

Right now, it is not doing *anything* useful as I'm in the hack-and-break phase.
In particular, the targets to scan are current hard-coded in main.c :-)

# Building

This needs https://github.com/okirch/libcurlies for handling configuration files.

Once you have that compiled and installed, you can build freemap.

There's a small configure script you need to run first, which does little more
than setting a bunch of path names. It supports the usual options like --prefix,
--etcdir, --bindir etc.

```
  ./configure --prefix /usr --etcdir /etc
  make
  make install
```

# Using

Rather than putting the entire scan process into one huge pipeline, freemap tries
to split this up into several stages that can be run independently. The idea is that
you may want to re-run parts of a scan, possibly with different arguments, without
having to watch it go through *all* the necessary paces.

```
  freemap init my_scan
```

This will initialize the current directory as a scan project, and place a configuration
file in there called `project.conf`. You can edit this file directly, or you can use
`freemap` to change settings for you.

```
  freemap add-targets 192.168.1.0/24
  freemap set topology-scan traceroute
  freemap set reachability-scan magicscan
  freemap set service-scan thorough
```

The first step is crucial, because it defines the scan target(s) you want to probe going
forward. If you do this, you can run any scan commands without specifying the targets
on the command line.

Subsequently, you can run individual probing steps:

```
  freemap topology-scan
  freemap host-scan
  freemap port-scan
```

A topology scan performs traceroute-like probes to understand which hops lie between
you and a target network; this information can be used in tuning packet rates and
for priming rtt estimates.

The host reachability scan performs various probes to identify hosts which are reachable
at all. Typically, this would be an ICMP ping or an ARP lookup, but other, more
exotic probes are possible as well.

Finally, the port scan will probe whether services are listening on UDP and TCP ports.
In the case of UDP, it is possible to define probing packets to send to the port,
in order to verify the kind of service that is running there.

All results from these probing activities are stored in sparse files within the project
directory. These are mapped into memory as needed. In particular, these files will
appear fairly large, but they usually occupy only a few blocks on disk - the rest is
holes.

Last but not least, the data that has been collected can be displayed using

```
  freemap report
```

This is possible even while a scan is ongoing, as the files are mapped into memory,
so any update is instantly visible to other processes.
