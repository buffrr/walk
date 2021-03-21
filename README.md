# Walk

DNS zone walking by following denial of existence proofs. It walks a zone by checking the next domain in the NSEC record.
For this to work, the zone must be DNSSEC signed.

This tool doesn't work for zones that use online signing.

## Usage

```
Usage: walk [@nameserver] [options] zone

[options]:
  -f    Do a full zone walk
  -p string
        Specify port number (default "53")
  -s string
        Start walk with this owner name
```

### Basic example

```bash
$ walk @1.1.1.1 ietf.org
_dmarc.ietf.org.  A NS SOA MX TXT AAAA RRSIG NSEC DNSKEY SPF
ietf1._domainkey.ietf.org.  TXT RRSIG NSEC
alt-meeting-sandbox.ietf.org.  TXT RRSIG NSEC
analytics.ietf.org.  CNAME RRSIG NSEC
...
```

### Full zone walk

This is dumps the ICANN root zone

```bash
$ walk @a.root-servers.net -f  .
```


## Credits

This project is based on [ldns-walk](https://linux.die.net/man/1/ldns-walk) written in C. 

## License

MIT