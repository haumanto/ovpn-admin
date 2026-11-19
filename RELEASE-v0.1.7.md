# ovpn-admin v0.1.7 release notes

**Status: not published.** Release candidate. There is no tag, GitHub release, GHCR image, binary or chart release for v0.1.7. Publishing needs a human decision.

- Candidate: branch `v0.1.7`, code SHA `a650881a7c8226083cc1097cd81596c2eefdb520`. It is two commits on top of v0.1.6 (`8fc3f23`): `550d2bc` (themes) and `a650881` (version bump). The commit that adds this file sits on top of `a650881` and changes only `RELEASE-v0.1.7.md`, `README.md` and `UPGRADING.md`.
- QA: `qa-v017/REPORT.md` (card `t_3fbeb6b9`), verdict **SHIP** at `a650881`. Items 1 to 13 PASS. Chromium 156, headless.
- Developer evidence (F17, `v017/`): `go vet` and `go test` for `ovpn-admin` passed (`r17-gotest.txt`); the frontend build compiled (`r17-npm-build.log`); the image reports `--version` `0.1.7` (`r17-image-build.log`, `r17-version.txt`).

Source tags below: `[QA n]` = QA report item n. `[F17]` = the developer evidence above.

## What changed since v0.1.6

- **Light, Dark and System themes.** A theme button in the top bar opens a menu with the three choices. `[QA 4]`
- **System is the default.** With no saved choice, the page follows the light or dark setting of the device. `[QA 2, 3]`
- **Live OS following.** While System is selected, a change of the device setting applies at once, with no reload. Light and Dark ignore the device setting. `[QA 5, 6]`
- **Per-browser choice.** The choice is saved in the browser only. It is not sent to the server and it is not a setting in the compose file. `[QA 5, 10]`
- **No flash on load.** The saved or System theme is applied before the first paint. `[QA 7]`
- **Version string** `0.1.7` in the Go binary, the chart and the frontend package. `[F17]`

## Themes

### Where the control is

The theme button is in the top bar, the first control in the right-hand group, left of **Refresh**. It shows a sun (Light), a moon (Dark) or a monitor (System). It is on the master and on the slave. QA checked it at 390 px and 1280 px. `[QA 4, 10]`

### Choosing a theme

1. Press the theme button, or press Enter or ArrowDown on it. The menu opens with focus on the current choice.
2. Pick **Light**, **Dark** or **System**. The choice applies at once and the menu closes.

On a phone the menu is a bottom sheet with a **Cancel** button. From 769 px it is a small menu under the button. The **System** line reads "Follows this device, now Dark" or "now Light". `[QA 4, 6]`

Keyboard: arrow keys move through the items, Home and End jump to the first and last, Enter or Space picks, and Esc closes without a change. Focus returns to the theme button. `[QA 4]`

### System

- System follows the light or dark setting of the device. A change of that setting while the page is open applies at once. `[QA 6]`
- Light and Dark do not change when the device setting changes. `[QA 6]`

### Saved choice

- A choice is kept after a reload. `[QA 5]`
- A browser with no saved choice shows System. A saved value that is not Light, Dark or System is ignored, and the page shows System. `[QA 2, 3]`
- If the browser blocks storage, the choice still applies until the page is closed. The next load shows System. No console error is logged. `[QA 11]`
- The master and the slave panels run on different ports, so they are separate origins. Each keeps its own choice. `[QA 10]`

### No flash

The theme is applied in the page head before the stylesheet loads. In QA, a page saved as Dark on a device set to Light showed a dark first frame in every sampled frame. No light frame was seen while the stylesheet was held back for about 3 seconds. `[QA 7]`

## Upgrade notes

Full steps: [UPGRADING.md](UPGRADING.md#v016--v017).

- **Rebuild the `ovpn-admin` image only.** The `openvpn` image is unchanged: `Dockerfile.openvpn` and `setup/` have no changes since v0.1.6. `[F17]`
- **No database migration.** The v0.1.6 to v0.1.7 diff touches only the frontend, `main.go` and the chart metadata. `easyrsa_master/`, `ccd_master/`, `users.db` and `audit_master/` are not changed by this release.
- **Theme is a local browser preference.** There is no server setting, no environment variable and no compose change for it.
- **Existing browsers have no stored choice.** v0.1.6 had no theme setting, so after the upgrade each browser shows System until the user picks a theme.

## Known limitations

- **One engine only.** Chromium 156, headless. Firefox, Safari and real phones were not tested. `[QA]`
- **Emulated conditions.** The device light or dark setting and blocked storage were simulated in the browser. No real OS setting was changed. `[QA Assumptions]`
- **Not rendered in QA.** Expired and "expires soon" badges, the offline banner, the loading skeleton, the load-error state, and the Add user, Set password, Revoke, Delete, Rotate and Routes dialogs. Their colours are covered by colour-pair checks only. Hover and pressed states were not rendered. `[QA Known limitations]`
- **Not tested.** `forced-colors` and `prefers-contrast`. A choice made in one tab reaching another open tab (the `storage` event). `[QA Known limitations]`
- **Contrast.** All measured text and UI pairs pass WCAG AA, both themes. The white label on the Dark primary button is the closest: 4.71:1 against 4.5:1 needed. `[QA 9]`
- **Cosmetic.** At 1280 px with a classic scrollbar, a 15 px strip to the right of the header shows the page colour, not the header colour, in both themes. It was not compared with v0.1.6. `[QA observation 3]`
- **Observed, not changed.** On phones the theme sheet's **Cancel** button is reachable with the arrow keys. Space also picks the focused item. `[QA observations 1, 2]`
- **Not re-run by QA.** Go tests, the frontend build log and the Helm chart. The Helm chart has only its version changed in this release. `[QA Known limitations] [F17]`
- **No in-place upgrade run.** QA used a fresh stack. An upgrade of an existing v0.1.6 install with data was not run. `[QA]`
- **Draft status.** This file is a draft until a human approves publishing. No tag, image, binary or chart release has been made.
