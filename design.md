# Architectural building blocks

## Address enumerator

Based on user input, enumerates the addresses to scan.

## Port enumerator

## Scan scheduler

This consumes addresses provided by an address enumerator, and schedules scans of address/port pairs.

In its simplest form, it takes a single address at a time, and iterates through all the ports to scan.
