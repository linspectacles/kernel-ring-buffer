<p align="center">
  <a href="https://github.com/brunonlinespace/brunonlinespace/blob/main/linspectacles/kernel-ring-buffer.png">
    <img
      src="https://raw.githubusercontent.com/brunonlinespace/brunonlinespace/main/linspectacles/kernel-ring-buffer.png"
      alt="Kernel Ring Buffer screenshot"
      width="900"
    >
  </a>
</p>

# Kernel Ring Buffer

**Expose. Explore. Explain.**

Kernel Ring Buffer is a read-only inspector for exactly one Linux source: the current kernel printk ring buffer exposed through `/dev/kmsg`.

Current release: **0.0.6**

Repository: <https://github.com/linspectacles/kernel-ring-buffer>

## What Kernel Ring Buffer is

Kernel Ring Buffer answers a focused question: **what native records does the kernel printk ring buffer contain, including the fields that formatted `dmesg` output can hide?**

It keeps acquisition and interpretation close to the Linux interfaces actually used by the applet. When a source is unavailable, restricted, or does not report a field, the README does not imply that the applet can manufacture the missing information.

## Highlights

- Reads `/dev/kmsg` directly instead of formatting the ring through `dmesg`.
- Preserves priority/facility codes, 64-bit sequence number, monotonic timestamp, flags and continuation state.
- Retains optional header extensions, `PRINTK_CALLER` when reported, continuation lines and machine-readable `KEY=VALUE` tags.
- Keeps decoded message plus raw header and raw `/dev/kmsg` record.
- Search, Facility and exact Priority filters operate on the acquired snapshot.
- Optional in-place privileged access uses a fixed helper that exposes only a read-only `/dev/kmsg` snapshot operation.
- Changing access mode invalidates the old dataset so ordinary and helper-sourced records are not mixed.

## Data sources and acquisition

- `/dev/kmsg` — this is the complete inspection source.

The applet uses those sources according to the acquisition paths implemented in this release. Optional tools or privileged helpers only affect the views/actions that explicitly use them; they are not treated as silent substitutes for unrelated sources.

## Interface

Kernel Ring Buffer follows the LinSpectacles inventory + **Metadata Details** pattern where applicable: an acquired inventory remains separate from the details for the selected record, and search/filter controls operate on the data the applet has actually collected.

The applet's **Options** surface provides the presentation/source/about controls implemented by this release, together with export controls where present in the source. Applet-specific actions remain explicit rather than being folded into background collection.

## Read-only and scope boundaries

The GUI never runs as root. The helper has one fixed read-only operation and is stopped when privileged access is turned off or the applet is deactivated/hidden. Kernel Ring Buffer does not use the journal as a substitute source and does not modify kernel logging state.

## Useful keyboard shortcuts

| Command | Shortcut |
| --- | --- |
| Show / hide Metadata Details | `F3` |
| Toggle Horizontal / Vertical details | `Ctrl+L` |
| Repeat current scan | `Shift+F5` |
| Options | `Ctrl+/` |
| Exact priority filters | `Ctrl+0` … `Ctrl+7`, `Ctrl+A`, `Ctrl+N` |

## Running from source

The supplied source is directly runnable on Linux. The Python-side requirements are:

- Python 3.
- PyQt6 for the graphical interface.

Create a local virtual environment if you do not already have the required Python packages in the environment you want to use:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install PyQt6
python3 linspectacles_kernel_ring_buffer/standalone.py
```

Linux commands, procfs/sysfs interfaces, system services, or optional helpers mentioned in **Data sources and acquisition** are applet-specific runtime inputs. A missing optional source is handled by the applet's existing availability/error path; it is not replaced here with an invented dependency or capability.

No RPM installation instructions are included in this README.

## Source layout and LinSpectacles integration

The applet source is contained in:

```text
linspectacles_kernel_ring_buffer/
├── __init__.py
├── applet.json
├── standalone.py
├── README.md
├── LICENSE
└── kernel_ring_buffer/
    ├── __init__.py
    ├── applet.py
    ├── _support.py
    ├── privilege.py
    ├── icon.png
    ├── README.md
    ├── PRIVILEGED.md
    ├── PRIVILEGED-HELPER-CONTRACT-v1.md
    └── privileged/
        ├── install-helper.sh
        └── linspectacles-kernel-ring-buffer-helper
```

`applet.json` supplies the LinSpectacles applet identity and entrypoint metadata. `standalone.py` launches the applet directly, while the package's applet factory provides the host-loadable LinSpectacles integration used by the source.

## Configuration

Presentation and inspection preferences are persisted only through the settings mechanisms already implemented by the applet. Persisted UI state does not grant the applet permission to modify the inspected Linux subsystem.

## Scope

Kernel Ring Buffer is intentionally specialist. Related Linux information that belongs to another LinSpectacles subsystem remains outside this applet rather than being inferred or duplicated here.

## License

GNU General Public License v3.0 or later. See [`LICENSE`](LICENSE).

## Links

- LinSpectacles organisation: <https://github.com/linspectacles/>
- Repository: <https://github.com/linspectacles/kernel-ring-buffer>
- Issues: <https://github.com/linspectacles/kernel-ring-buffer/issues>

<p align="center">
  <a href="https://github.com/linspectacles/kernel-ring-buffer">
    <img
      src="kernel_ring_buffer/icon.png"
      alt="Kernel Ring Buffer"
      width="256"
    >
  </a>
</p>
