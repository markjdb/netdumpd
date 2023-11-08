# Summary
Netdump is a daemon that accepts network core dumps

# How to build
## With Capsicum
```
make
```

## Without Capsicum
```
# Requires FreeBSD 13 or higher
make WITHOUT_CAPSICUM=1
```
