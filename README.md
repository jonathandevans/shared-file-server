# Shared File Server

The directory setup is assuming that your are on a lab machine, so the certificate files sync across the machines. Otherwise, they can all be run locally, which is the default setup.

## Certificate Authority (CA)

The `cert-auth.sh` needs to be run first to generate the CA certificate and key.

```bash
./cert-auth.sh
```

## Server

The `server.sh` needs to be run after the CA has been generated. It will generate the server certificate and key.

```bash
./server.sh
```

## Client

The `client.sh` needs to be run after the CA has been generated. It will generate the client certificate and key. This script will create a copy of the client code for the instance number, allowing multiple clients to be run.

```bash
./client-instance.sh <number>
```

## Clean Up

The `tidy.sh` script will remove all the generated files, including the client instances.

```bash
./tidy.sh
```