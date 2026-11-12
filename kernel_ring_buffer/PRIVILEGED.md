# Optional Privileged Access

Kernel Ring Buffer normally opens `/dev/kmsg` as the logged-in user.

If Linux restricts that interface, the top-level **Privileged: Off** button starts the verified optional helper through PolicyKit. Privilege is **in-place**: the GUI itself is never elevated and no second inspector window is created.

While active:
- the button reads **Privileged: On** and uses the amber privileged treatment;
- scans use the helper to read the same `/dev/kmsg` source;
- helper-sourced inventory rows are amber;
- Metadata Details uses the established SELinux privileged palette;
- records report `Access: Privileged Helper`.

Turning privileged access off, changing away from the applet, hiding/deactivating the applet, shutdown, or application exit terminates the helper. Access-mode changes clear the current dataset before another scan.

Helper management is available under **Options → Helper**.
