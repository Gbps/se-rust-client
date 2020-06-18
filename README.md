# Emulating a source client signon

Source engine's signon process has gotten significantly more complicated over the years as CS:GO has transitioned to matchmaking rather than direct IP connection. In addition, the invention of Steam Game Sockets means that now the traffic that's being communicated between the client and the server is being proxied over a relay network embedded in the Steam backbone.

For this purpose, I'm focusing on the most basic kind of gameserver connection, one that is done directly over UDP to a target port.

For this project, I decided to use Rust to implement the networking... because why not, it's fun and I'm learning the new language.

## Connectionless Packets

