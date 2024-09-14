# nostr-mute

cli for Nostr mute list 

## Usage

You need to set two environment variables

* `NOSTR_MUTE_NSEC` - your nsec
* `NOSTR_MUTE_RELAYS` - your relays comma separated

If you want to manipulate non-encrypted mute list, please add `-encrypt=false` like below

```
nostr-mute -encrypt=false list
```

### List mute 

```
nostr-mute add -e note1xxxx
```
### Add one npub

```
nostr-mute add -p npub1xxxx
```

### Add one note

```
nostr-mute add -e note1xxxx
```

### Export mute list

```
nostr-mute export > mute.json
```

### Import mute list

```
nostr-mute import < mute.json
```

### Import p mute list

```
nostr-mute import-p < mute.txt
```

`mute.txt` is text file listed npub(s) like below.

```
npub10nryfp7p3kgd2m6xrx6euw2360xt4tcr9e794qnwudxtyqzapqcskaalqg
npub1sucfl8rzfej4aj6tynm80wwxtex20mlh7086umygf5pd8h4mdjss52h59m
npub1fuvf4meqywhzscdlf8g7gt9sgedy5xg92wgtsruha4d6lefekzfsuwynev
```

## Installation

```
go install github.com/mattn/nostr-mute@latest
```

## License

MIT

## Author

Yasuhiro Matsumoto (a.k.a. mattn)
