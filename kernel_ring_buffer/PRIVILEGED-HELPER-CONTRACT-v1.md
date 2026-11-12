# LinSpectacles Privileged Helper Contract v1 — Kernel Ring Buffer

Kernel Ring Buffer `0.0.5` declares an optional `in_place_ephemeral`, read-only helper.

The GUI itself is never elevated. The helper is started only after explicit PolicyKit authorization from the existing applet and is stopped when privileged access is disabled or the applet shuts down.

The helper exposes exactly one fixed operation:

- `kmsg_snapshot` — open `/dev/kmsg` read-only/non-blocking, seek to the oldest retained record available to that reader, return records until the current end, and close the descriptor.

There is no arbitrary command execution, arbitrary path reading, write operation, buffer clearing, console manipulation, or persistent background process.

The installed helper must be a regular root-owned executable, not writable by group/other, and must match the exact SHA-256 declared in `applet.json`.
