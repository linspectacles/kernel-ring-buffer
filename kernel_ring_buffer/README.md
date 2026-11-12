# Kernel Ring Buffer 0.0.6

Kernel Ring Buffer is a read-only LinSpectacles applet for exactly one Linux source:

`/dev/kmsg`

It is the renamed and simplified successor to the experimental kernel-ring-only Kernel Ring Buffer line.

## Native record model

The applet reads `/dev/kmsg` directly rather than formatting the ring through `dmesg`. Each retained record preserves:

- combined syslog prefix;
- priority and facility codes plus names;
- 64-bit sequence number;
- monotonic timestamp in microseconds plus readable monotonic time;
- flags and continuation/fragment state;
- every optional comma-separated header extension;
- `PRINTK_CALLER` when the kernel reports it;
- every continuation line and machine-readable `KEY=VALUE` tag such as `SUBSYSTEM=` and `DEVICE=`;
- unknown future header/context fields;
- decoded message;
- raw header and exact raw `/dev/kmsg` record.

Inventory columns:

`Sequence | Monotonic Time | Priority | Facility | Caller | Flags | Subsystem | Device | Message`

Filters:

`Search | Priority | Facility`

## Privilege

Privilege follows Resource Monitor's **in-place** model.

The GUI never runs as root. `Privileged: On` starts the verified root-owned helper through PolicyKit; the same applet then reads the same `/dev/kmsg` source through that helper. Turning privileged access off or leaving the applet stops the helper.

Changing access mode invalidates the existing dataset so ordinary and helper-sourced records can never be confused.

Helper-derived inventory rows use the ResMon provenance treatment (`#e5bd70`). Metadata Details switches to the SELinux privileged palette while privileged access is active:

- keys/headings `#f2d18b`
- values `#e5bd70`
- neutral text `#dcdcdc`
- background `#1e1e1e`
- status background `#3a2d13`
- status text `#f2d18b`

The helper exposes exactly one fixed read-only operation: snapshot `/dev/kmsg`.

## Sources

`/dev/kmsg`

That is the complete Sources list.

## exp1-r1

### Privilege lifecycle
Privilege is now genuinely ephemeral at the applet boundary. The helper is
stopped when the Suite deactivates Kernel Ring Buffer and also when the widget
is hidden, covering hosts that switch applets through a stacked widget without
calling the lifecycle hook. Privileged-derived records are invalidated by the
existing access-change path and a return to the applet requires fresh explicit
authorization.

### Top-level order
The right side of the title row is now:

`[privilege message] [Privilege button] [Scan / Scan Again] [Options...]`

### Filters
The filter row is:

`Search | Facility | Priority`

Facility is given at least the natural width of the existing Priority selector.

### Appearance and shortcuts
Options → **Appearance** contains the display settings.

- `F3` — show/hide Metadata Details
- `Ctrl+L` — toggle horizontal/vertical details layout
- `Shift+F5` — repeat the current scan

Metadata-panel visibility and details orientation are persistent.

### Sources
Options → Sources now copies Journal Inspector 0.0.4-r1 precisely:
`#151719` canvas, `#dcdcdc` values, `#333333` border, and bold
`#9cdcfe` headings/keys.

## exp1-r2

### Privilege surface simplification
The live privilege-status label beside the button has been removed. The
Privileged button and the ordinary status bar are now the only live privilege
state surfaces on the main applet.

The explanatory provenance statement is static in Options → Helper:

`Privileged read-only /dev/kmsg access · amber data = helper-sourced`

The r1 deactivation/hide lifecycle remains unchanged.

### Priority filter shortcuts
These shortcuts set the existing local exact Priority filter:

- `Ctrl+0` — Emergency
- `Ctrl+1` — Alert
- `Ctrl+2` — Critical
- `Ctrl+3` — Error
- `Ctrl+4` — Warning
- `Ctrl+5` — Notice
- `Ctrl+6` — Informational
- `Ctrl+7` — Debug
- `Ctrl+A` — All
- `Ctrl+N` — Not reported

F3 and Shift+F5 remain unchanged; Ctrl+L now toggles the Horizontal/Vertical details layout.
