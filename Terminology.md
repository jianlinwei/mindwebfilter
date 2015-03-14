# Used Terminology #

## Introduction ##
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14, RFC 2119 [2](2.md).

The special terminology used in this document is defined below.  The
majority of these terms are taken as-is from HTTP/1.1 [4](4.md) and are
reproduced here for reference.  A thorough understanding of HTTP/1.1
is assumed on the part of the reader.

## Terms ##
connection:
A transport layer virtual circuit established between two programs
for the purpose of communication.

message:
The basic unit of HTTP communication, consisting of a structured
sequence of octets matching the syntax defined in Section 4 of
HTTP/1.1 [4](4.md) and transmitted via the connection.

request:
An HTTP request message, as defined in Section 5 of HTTP/1.1 [4](4.md).

response:
An HTTP response message, as defined in Section 6 of HTTP/1.1 [4](4.md).

resource:
A network data object or service that can be identified by a URI,
as defined in Section 3.2 of HTTP/1.1 [4](4.md).  Resources may be
available in multiple representations (e.g., multiple languages,
data formats, size, resolutions) or vary in other ways.

client:
A program that establishes connections for the purpose of sending
requests.

server:
An application program that accepts connections in order to
service requests by sending back responses.  Any given program may
be capable of being both a client and a server; our use of these
terms refers only to the role being performed by the program for a
particular connection, rather than to the program's capabilities
in general. Likewise, any server may act as an origin server,
surrogate, gateway, or tunnel, switching behavior based on the
nature of each request.

origin server:
The server on which a given resource resides or is to be created.

proxy:
An intermediary program which acts as both a server and a client
for the purpose of making requests on behalf of other clients.
Requests are serviced internally or by passing them on, with
possible translation, to other servers.  A proxy MUST implement
both the client and server requirements of this specification.

cache:
A program's local store of response messages and the subsystem
that controls its message storage, retrieval, and deletion.  A
cache stores cachable responses in order to reduce the response
time and network bandwidth consumption on future, equivalent
requests.  Any client or server may include a cache, though a
cache cannot be used by a server that is acting as a tunnel.

cachable:
A response is cachable if a cache is allowed to store a copy of
the response message for use in answering subsequent requests.
The rules for determining the cachability of HTTP responses are
defined in Section 13 of [4](4.md).  Even if a resource is cachable,
there may be additional constraints on whether a cache can use the
cached copy for a particular request.

surrogate:
A gateway co-located with an origin server, or at a different
point in the network, delegated the authority to operate on behalf
of, and typically working in close co-operation with, one or more
origin servers.  Responses are typically delivered from an
internal cache.  Surrogates may derive cache entries from the
origin server or from another of the origin server's delegates.
In some cases a surrogate may tunnel such requests.

Where close co-operation between origin servers and surrogates
exists, this enables modifications of some protocol requirements,
including the Cache-Control directives in [4](4.md).  Such modifications
have yet to be fully specified.

Devices commonly known as "reverse proxies" and "(origin) server
accelerators" are both more properly defined as surrogates.

ICAP resource:
Similar to an HTTP resource as described above, but the URI refers
to an ICAP service that performs adaptations of HTTP messages.

ICAP server:
Similar to an HTTP server as described above, except that the
application services ICAP requests.

ICAP client:
A program that establishes connections to ICAP servers for the
purpose of sending requests.  An ICAP client is often, but not
always, a surrogate acting on behalf of a user.