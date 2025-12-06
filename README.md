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

## Initialize your scan project

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

Freemap can set up your scan configuration using so-called presets which define a
set of probes and ports. Initially, it will use the preset "default".

You can modify your scan configuration in two ways. One is to select a different preset,
like this:

```
  freemap configure preset local
```

A list of available presets can be obtained using

```
  freemap info presets
```

The other approach to tuning your scan configuration is by editing the project.conf file
in your scan project. The ins and outs of that will be explained in a separate document
(which still needs to be written).


## Configure your scan targets

This step is optional, because you can invoke all scan commands with one or more targets
given as command line arguments. However, having the list of targets defined in your
project configuration may be more convenient. It can be done like this:

```
  freemap add-targets 192.168.1.0/24
```

## Running your scan

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
