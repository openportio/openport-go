# Openport and systemd

## For Users

There are two ways to manage persistent openport sessions. Traditionally, the
system is set to run `openport restart-sessions` on boot (via an init script)
which will resume whatever had been originally run with `--restart-on-boot`.
This model allows for ad-hoc sessions to be added to the list of start-on-boot
sessions.

Alternatively you can instead let systemd manage sessions. The included
Unit file allows for you to start various sessions, have systemd manage
them, and have the logs go into the journal.

To start an openport session that forward to port 22, you can do:

```bash
systemctl start openport@22
```

Or, to set systemd to start such a session on boot:

```bash
systemctl enable openport@22
```

When using the system unit file, openport is _not_ started with
`restart-sessions`, and so while you may still start adhoc sessions, the the
`--restart-on-reboot` flag will have no effect.

If you have additional options you would like to pass to _all_ openport
sessions you can set the OPTIONS variable in `/etc/default/openport` or `/etc/sysconfig/openport`, whichever is appropriate for your distribution. For example:

```bash
OPTIONS="--keep-alive 120"
```

If you would like to set options only for a specific sesion, you can set the
OPTIONS variable in `/etc/{default,sysconfig}/openport-<port>` (e.g.
`/etc/sysconfig/openport-22`). Note that setting OPTIONS in a session-specific
file will overwrite any OPTIONS variable in the non-session-specific file.

It is worth noting that many distributions ship only the init script which
systemd then uses to auto-generate an ephemeral unit on boot. In such
situations, you are using the non-systemd method here - all systemd is doing is
starting `openport restart-sessions`, which starts a separate process to start
and babysit any start-on-boot sessions, and then exits (meaning systemd manages
neither the parent openport nor any of the individual sessions). In such a
case, your service will simply be 'openport` instead of `openport@<port>`.

If your distribution ships _both_ an init script and the unit file, it is
recommended you choose one model to use and disable the other.

If your distribution does not ship the unit file but you'd like to use the
one in this repo simply install it in `/etc/systemd/system/openport@.service`,
and disable the ephemeral one:

```bash
systemctl stop openport
systemctl disable openport
```

And start services for any ports you want openport to forward to. For example:

```bash
systemctl enable opeport@22
systemctl start openport@22
```

## For Packagers

The unit file in this repository is designed to work on both Fedora- and
Debian- based systems (it supports `/etc/sysconfig` _and_ `/etc/default`).

If you package openport for a distribution that uses systemd, you should
probably _only_ include the unit file and not the init script. Including both
will be unclear what started a session in fact both mechanisms could end up
trying to start the same session.
