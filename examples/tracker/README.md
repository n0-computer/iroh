# Iroh content tracker

This is an example how to write a simple service using mostly iroh-net.
The purpose of this service is to track providers of iroh content.

You can *announce* to a tracker that you believe some host has some content.
The tracker will then periodically *verify* that the content is present.
Finally, you can *query* a tracker for hosts for a content.

## Running the tracker

```sh
tracker server
```

Will run the server with a persistent node id and announce information.

## Announcing content

When announcing content, you can give either iroh tickets or content hashes.

```sh
tracker announce \
    --tracker t3od3nblvk6csozc3oe7rjum7oebnnwwfkebolbxf2o66clzdyha \
    blob:ealcoyhcjxyklzee4manl3b5see3k3nwekf6npw5oollcsflrsduiaicaiafetezhwjouayaycuadbes5ibqaq7qasiyqmqo74ijal7k7ec4pni5htntx4tpoawgvmbhaa3txa4uaa
```

## Querying content

When querying content, you can use tickets, hashes, or hash and format.

When using tickets, the address part of the ticket will be ignored.

```sh
tracker query \
    --tracker t3od3nblvk6csozc3oe7rjum7oebnnwwfkebolbxf2o66clzdyha \
    blob:ealcoyhcjxyklzee4manl3b5see3k3nwekf6npw5oollcsflrsduiaicaiafetezhwjouayaycuadbes5ibqaq7qasiyqmqo74ijal7k7ec4pni5htntx4tpoawgvmbhaa3txa4uaa
```

## Verification

Verification works in different ways depending if the content is partial or
complete.

For partial content, the tracker will just ask for the unverified content size.
That's the only thing you can do for a node that possibly has just started
downloading the content itself.

For full content and blobs, the tracker will choose a random blake3 chunk of the
data and download it. This is relatively cheap in terms of traffic (2 KiB), and
since the chunk is random a host that has only partial content will be found
eventually.

For full content and hash sequences such as collections, the tracker will choose
a random chunk of a random child.
