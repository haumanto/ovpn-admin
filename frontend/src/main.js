import { createApp, markRaw } from 'vue';
import axios from 'axios';
import Notifications from '@kyvg/vue3-notification'
import VueGoodTablePlugin from 'vue-good-table-next'

var axios_cfg = function(url, data='', type='form') {
  if (data == '') {
    return {
      method: 'get',
      url: url
    };
  } else if (type == 'form') {
    return {
      method: 'post',
      url: url,
      data: data,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    };
  } else if (type == 'file') {
    return {
      method: 'post',
      url: url,
      data: data,
      headers: { 'Content-Type': 'multipart/form-data' }
    };
   } else if (type == 'json') {
    return {
      method: 'post',
      url: url,
      data: data,
      headers: { 'Content-Type': 'application/json' }
    };
  }
};

// Human readable message of a failed axios request: the backend answers with
// plain text (http.Error) or with {"status": "...", "message": "..."}.
var errorMessage = function(error) {
  if (!error.response) {
    return error.message || String(error);
  }
  var data = error.response.data;
  if (data && typeof data === 'object') {
    return data.message || data.status || JSON.stringify(data);
  }
  if (data) {
    return String(data).trim();
  }
  return error.response.statusText || ('HTTP ' + error.response.status);
};

// Minimal document.cookie helper (replaces vue-cookies, same cookie format:
// URI-encoded value, path=/, never expires).
var cookies = {
  get: function(name) {
    var prefix = encodeURIComponent(name) + '=';
    var parts = document.cookie ? document.cookie.split('; ') : [];
    for (var i = 0; i < parts.length; i++) {
      if (parts[i].indexOf(prefix) === 0) {
        try {
          return decodeURIComponent(parts[i].substring(prefix.length));
        } catch (e) {
          return null;
        }
      }
    }
    return null;
  },
  set: function(name, value) {
    document.cookie = encodeURIComponent(name) + '=' + encodeURIComponent(String(value)) +
      '; expires=Fri, 31 Dec 9999 23:59:59 GMT; path=/; SameSite=Lax';
  }
};

// navigator.clipboard is only available in secure contexts (https or
// localhost), ovpn-admin is often served over plain http.
var legacyCopyToClipboard = function(text) {
  return new Promise(function(resolve, reject) {
    var textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.setAttribute('readonly', '');
    textarea.style.position = 'fixed';
    textarea.style.top = '0';
    textarea.style.left = '0';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    var copied = false;
    try {
      copied = document.execCommand('copy');
    } catch (e) {
      copied = false;
    }
    document.body.removeChild(textarea);
    if (copied) {
      resolve();
    } else {
      reject(new Error('copy command is not supported'));
    }
  });
};

var copyToClipboard = function(text) {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text).catch(function() {
      return legacyCopyToClipboard(text);
    });
  }
  return legacyCopyToClipboard(text);
};

var emptyCcd = function() {
  return {
    User: '',
    ClientAddress: '',
    ClientAddressIPv6: '',
    CustomRoutes: []
  };
};

var emptyRoute = function() {
  return {
    Address: '',
    Mask: '',
    Description: ''
  };
};

// number of events the login history dialog asks for
var HISTORY_LIMIT = 50;

// Missing/empty ClientAddress or ClientAddressIPv6 means "dynamic".
var normalizeCcd = function(ccd, username) {
  ccd = (ccd && typeof ccd === 'object') ? ccd : {};
  return {
    User: ccd.User || username,
    ClientAddress: ccd.ClientAddress || 'dynamic',
    ClientAddressIPv6: ccd.ClientAddressIPv6 || 'dynamic',
    CustomRoutes: Array.isArray(ccd.CustomRoutes) ? ccd.CustomRoutes : []
  };
};

// ---- formatting helpers (design-spec sections 1, 2 and 3) ----

var pad2 = function(n) {
  return (n < 10 ? '0' : '') + n;
};

var plural = function(n, unit) {
  return n + ' ' + unit + (n === 1 ? '' : 's');
};

// 'YYYY-MM-DD HH:MM[:SS]' in the browser time zone.
var formatLocal = function(date, seconds) {
  var s = date.getFullYear() + '-' + pad2(date.getMonth() + 1) + '-' + pad2(date.getDate()) +
    ' ' + pad2(date.getHours()) + ':' + pad2(date.getMinutes());
  return seconds ? s + ':' + pad2(date.getSeconds()) : s;
};

var formatUtcSeconds = function(date) {
  return date.getUTCFullYear() + '-' + pad2(date.getUTCMonth() + 1) + '-' + pad2(date.getUTCDate()) +
    ' ' + pad2(date.getUTCHours()) + ':' + pad2(date.getUTCMinutes()) + ':' + pad2(date.getUTCSeconds());
};

var formatClock = function(date) {
  return pad2(date.getHours()) + ':' + pad2(date.getMinutes());
};

// 'UTC+07:00' from the browser offset.
var offsetLabel = function() {
  var offset = -new Date().getTimezoneOffset();
  var abs = Math.abs(offset);
  return 'UTC' + (offset < 0 ? '-' : '+') + pad2(Math.floor(abs / 60)) + ':' + pad2(abs % 60);
};

var startOfDay = function(date) {
  return new Date(date.getFullYear(), date.getMonth(), date.getDate()).getTime();
};

// calendar days from today to date (negative: in the past)
var dayDiff = function(date, nowMs) {
  return Math.round((startOfDay(date) - startOfDay(new Date(nowMs))) / 86400000);
};

// 12 days / 2 months / 3 years (30-day months, floor, at least 1)
var daysSpan = function(days) {
  if (days < 30) {
    return plural(days, 'day');
  }
  if (days < 365) {
    return plural(Math.max(1, Math.floor(days / 30)), 'month');
  }
  return plural(Math.floor(days / 365), 'year');
};

// Relative time of a past instant. Future instants (clock skew) read 'just now'.
var relativePast = function(ts, nowMs) {
  var s = Math.floor((nowMs - ts) / 1000);
  if (s < 60) {
    return 'just now';
  }
  if (s < 3600) {
    return plural(Math.floor(s / 60), 'minute') + ' ago';
  }
  if (s < 86400) {
    return plural(Math.floor(s / 3600), 'hour') + ' ago';
  }
  if (dayDiff(new Date(ts), nowMs) === -1) {
    return 'yesterday';
  }
  var days = Math.floor(s / 86400);
  if (days < 30) {
    return plural(days, 'day') + ' ago';
  }
  if (days < 365) {
    return plural(Math.max(1, Math.floor(days / 30)), 'month') + ' ago';
  }
  return plural(Math.floor(days / 365), 'year') + ' ago';
};

// The backend sends 'yyyy-MM-dd HH:mm:ss' without a zone.
var parseExpiry = function(value) {
  if (!value) {
    return null;
  }
  var d = new Date(String(value).replace(' ', 'T'));
  return isNaN(d.getTime()) ? null : d;
};

var EXPIRY_WARN_DAYS = 30;

var expiryInfo = function(row, nowMs) {
  var raw = row.ExpirationDate || '';
  var d = parseExpiry(raw);
  if (!d) {
    return { date: raw || '—', text: '', warn: false };
  }
  var diff = dayDiff(d, nowMs);
  var date = String(raw).substring(0, 10);
  // a revoked certificate's expiry is not a call to action
  var warnAllowed = row.AccountStatus !== 'Revoked';
  if (diff < 0 || row.AccountStatus === 'Expired') {
    var n = Math.max(0, -diff);
    var past = n === 0 ? 'Expired today' : (n === 1 ? 'Expired yesterday' : 'Expired ' + daysSpan(n) + ' ago');
    return { date: date, text: past, warn: warnAllowed };
  }
  if (diff === 0) {
    return { date: date, text: 'Expires today', warn: warnAllowed };
  }
  if (diff === 1) {
    return { date: date, text: 'Expires tomorrow', warn: warnAllowed };
  }
  if (diff < EXPIRY_WARN_DAYS) {
    return { date: date, text: 'Expires in ' + plural(diff, 'day'), warn: warnAllowed };
  }
  return { date: date, text: 'in ' + daysSpan(diff), warn: false };
};

// ---- banned IPs (GET api/bans) ----

// Unix seconds (number or numeric string, as in bans.tsv) or an RFC 3339
// string; returns epoch milliseconds, 0 when unusable.
var parseTimestamp = function(value) {
  if (value === null || value === undefined || value === '') {
    return 0;
  }
  if (typeof value === 'number' || /^\d+(\.\d+)?$/.test(String(value).trim())) {
    var n = Number(value);
    // seconds (10 digits) vs milliseconds (13 digits)
    return n < 1e11 ? n * 1000 : n;
  }
  var ms = Date.parse(String(value));
  return isNaN(ms) ? 0 : ms;
};

// Relative time of a future instant: 'in 46 min', 'in 2 h 5 min', 'in 3 days'.
var relativeFuture = function(ts, nowMs) {
  var s = Math.floor((ts - nowMs) / 1000);
  if (s < 60) {
    return 'in under a minute';
  }
  var min = Math.floor(s / 60);
  if (min < 60) {
    return 'in ' + min + ' min';
  }
  var h = Math.floor(min / 60);
  if (h < 24) {
    return 'in ' + h + ' h' + (min % 60 ? ' ' + (min % 60) + ' min' : '');
  }
  return 'in ' + plural(Math.floor(h / 24), 'day');
};

// 'HH:MM' for today, 'MM-DD HH:MM' for other days (browser time zone).
var formatShortLocal = function(date, nowMs) {
  var hm = pad2(date.getHours()) + ':' + pad2(date.getMinutes());
  if (dayDiff(date, nowMs) === 0) {
    return hm;
  }
  return pad2(date.getMonth() + 1) + '-' + pad2(date.getDate()) + ' ' + hm;
};

var REASON_LABELS = {
  'revoked-certificate': 'Revoked certificate',
  'auth-failed': 'Authentication failed',
  'fail2ban': 'Repeated failures'
};

// The ban engine writes one word or two joined by '+'. Unknown values are
// shown as they are: the UI never hides server data.
var reasonLabel = function(reason) {
  if (!reason) {
    return 'No reason recorded';
  }
  // a manual ban is written as 'manual' or 'manual: <note>'; the note may contain any character, '+' included
  var manual = /^manual(?:: (.*))?$/.exec(String(reason));
  if (manual) {
    return manual[1] ? 'Manual ban: ' + manual[1] : 'Manual ban';
  }
  return String(reason).split('+').map(function(part) {
    return REASON_LABELS[part] || part;
  }).join(' + ');
};

var normalizeBan = function(b) {
  b = (b && typeof b === 'object') ? b : {};
  // a permanent ban has permanent: true and an empty expires_at; it never expires on its own
  var permanent = b.permanent === true;
  return {
    ip: String(b.ip || ''),
    permanent: permanent,
    bannedMs: parseTimestamp(b.banned_at),
    expiresMs: permanent ? 0 : parseTimestamp(b.expires_at),
    failures: Number(b.failures) || 0,
    reason: String(b.reason || ''),
    reasonLabel: reasonLabel(b.reason)
  };
};

var viewFromHash = function() {
  return window.location.hash === '#bans' ? 'bans' : 'users';
};

// Adds the derived fields the ban cards and rows read.
var decorateBan = function(b, nowMs) {
  var since = b.bannedMs ? new Date(b.bannedMs) : null;
  var exp = !b.permanent && b.expiresMs ? new Date(b.expiresMs) : null;
  return Object.assign({}, b, {
    _since: since ? {
      relative: relativePast(b.bannedMs, nowMs),
      short: formatShortLocal(since, nowMs),
      full: formatLocal(since, false),
      utc: formatUtcSeconds(since)
    } : null,
    _exp: exp ? {
      relative: b.expiresMs > nowMs ? relativeFuture(b.expiresMs, nowMs) : 'expired',
      short: formatShortLocal(exp, nowMs),
      full: formatLocal(exp, false),
      utc: formatUtcSeconds(exp)
    } : null,
    // past its expiry before the next refresh: the row stays, dimmed
    _expired: !b.permanent && b.expiresMs > 0 && b.expiresMs <= nowMs
  });
};

// Manual ban form. The note limit and character set are those of the ban
// watcher (setup/ovpn-ban-control.py); the server checks everything again.
var BAN_NOTE_MAX = 120;
var validateBanIp = function(value) {
  var ip = String(value || '').trim();
  if (ip === '') {
    return 'Enter an IP address.';
  }
  if (!/^[0-9A-Fa-f:.]{2,45}$/.test(ip) || (ip.indexOf('.') < 0 && ip.indexOf(':') < 0)) {
    return 'Enter an IPv4 or IPv6 address, for example 203.0.113.9.';
  }
  return '';
};
var validateBanNote = function(value) {
  var note = String(value || '');
  if (note.length > BAN_NOTE_MAX) {
    return 'The note is longer than ' + BAN_NOTE_MAX + ' characters.';
  }
  if (!/^[A-Za-z0-9 ._:-]*$/.test(note)) {
    return 'Use letters, digits, spaces and . _ : - only.';
  }
  return '';
};

var BANS_POLL_MS = 30000;
var BANS_POLL_BACKOFF_MS = 120000;
var BANS_BACKOFF_AFTER = 3;
var BANS_COUNT_POLL_MS = 60000;
var BANS_SEARCH_MIN_ROWS = 200;

// Body scroll lock shared by dialogs and menus (counted, scroll position is
// restored: iOS keeps the page offset otherwise).
var scrollLock = {
  count: 0,
  y: 0,
  lock: function() {
    if (this.count === 0) {
      this.y = window.pageYOffset || 0;
      document.body.classList.add('ov-scroll-locked');
    }
    this.count++;
  },
  unlock: function() {
    if (this.count === 0) {
      return;
    }
    this.count--;
    if (this.count === 0) {
      document.body.classList.remove('ov-scroll-locked');
      if ((window.pageYOffset || 0) !== this.y) {
        window.scrollTo(0, this.y);
      }
    }
  }
};

// Decimal units: 999 -> '999 B', 1203554810 -> '1.2 GB'.
var formatBytes = function(n) {
  n = Number(n) || 0;
  if (n < 1000) {
    return n + ' B';
  }
  var units = ['kB', 'MB', 'GB', 'TB'];
  var value = n / 1000;
  var i = 0;
  while (i < units.length - 1 && Number(value.toFixed(1)) >= 1000) {
    value /= 1000;
    i++;
  }
  return value.toFixed(1) + ' ' + units[i];
};

var EVENT_LABELS = {
  connect: 'Connected',
  disconnect: 'Disconnected',
  auth_ok: 'Password accepted',
  auth_fail: 'Login rejected'
};

var STATUS_RANK = { Online: 0, Active: 1, Expired: 2, Revoked: 3 };

// Adds the derived fields the table cells and sort functions read.
var decorateRow = function(row, nowMs) {
  var online = row.AccountStatus === 'Active' && row.ConnectionStatus === 'Connected';
  var label = online ? 'Online' : (row.AccountStatus || '');
  var badgeClass = 'ov-badge-active';
  var note = '';
  var sessions = 0;
  if (online) {
    badgeClass = 'ov-badge-online';
    sessions = Math.max(1, Number(row.Connections) || 0);
    note = plural(sessions, 'session');
  } else if (row.AccountStatus === 'Expired') {
    badgeClass = 'ov-badge-expired';
  } else if (row.AccountStatus === 'Revoked') {
    badgeClass = 'ov-badge-revoked';
    note = row.RevocationDate ? 'since ' + String(row.RevocationDate).substring(0, 10) : '';
  }
  var ts = row.LastLogin ? Date.parse(row.LastLogin) : NaN;
  var login = null;
  if (!isNaN(ts)) {
    login = {
      local: formatLocal(new Date(ts), false),
      utc: formatUtcSeconds(new Date(ts)),
      relative: relativePast(ts, nowMs)
    };
  }
  return Object.assign({}, row, {
    _statusLabel: label,
    _badgeClass: badgeClass,
    _statusNote: note,
    _sessions: sessions,
    _rank: label in STATUS_RANK ? STATUS_RANK[label] : 1,
    _loginTs: isNaN(ts) ? 0 : ts,
    _login: login,
    _expiry: expiryInfo(row, nowMs)
  });
};

// Sort functions. vue-good-table-next hangs on inconsistent comparators, so
// all of them are plain three-way compares ("No record" sorts as oldest).
var compareValues = function (x, y) {
  return x < y ? -1 : (x > y ? 1 : 0);
};
var compareNames = function (x, y) {
  return compareValues(String(x || '').toLowerCase(), String(y || '').toLowerCase());
};
var compareDateStrings = function (x, y) {
  return compareValues(x || '', y || '');
};

var USERNAME_RE = /^[a-zA-Z0-9_.\-@]+$/;

var validateUsername = function(name) {
  if (name === '') {
    return 'Enter a username.';
  }
  if (name === '.' || name === '..') {
    return 'This name is not allowed.';
  }
  if (!USERNAME_RE.test(name)) {
    return 'Use only letters, digits, and . _ - @ (no spaces).';
  }
  return '';
};

var validatePassword = function(password) {
  if (Array.from(password).length < 6) {
    return 'Use at least 6 characters.';
  }
  // the password hash takes at most 72 bytes, a multi-byte character counts for 2 to 4
  return new TextEncoder().encode(password).length > 72 ? 'Use at most 72 bytes (a non-ASCII character takes 2 to 4).' : '';
};

var trimPeriod = function(message) {
  return String(message).trim().replace(/\.+$/, '');
};

var dialogCounter = 0;

// Modal dialog shared by every dialog of the app (design-spec change 3):
// role=dialog, focus on open, Tab trap, Escape closes unless busy, focus
// returns to the opener. A click on the backdrop does nothing.
var AppDialog = {
  props: {
    title: { type: String, required: true },
    size: { type: String, default: 'sm' },
    busy: { type: Boolean, default: false },
    flush: { type: Boolean, default: false },
    describeBody: { type: Boolean, default: false },
    initialFocus: { type: String, default: 'first' }
  },
  emits: ['close'],
  data() {
    dialogCounter++;
    return { uid: 'dialog-' + dialogCounter };
  },
  template: '<div class="ov-backdrop" @mousedown="onBackdropDown" @click="onBackdropClick">' +
    '<div class="ov-dialog" :class="\'ov-dialog-\' + size" role="dialog" aria-modal="true" ref="box" ' +
    ':aria-labelledby="uid + \'-title\'" :aria-describedby="describeBody ? uid + \'-body\' : null">' +
    '<div class="ov-dialog-head"><div class="ov-dialog-titles"><h2 class="ov-dialog-title" :id="uid + \'-title\'">{{ title }}</h2>' +
    '<p class="ov-dialog-meta" v-if="$slots.meta"><slot name="meta"></slot></p></div>' +
    '<button type="button" class="ov-btn ov-btn-ghost ov-btn-icon ov-dialog-x" aria-label="Close" :disabled="busy" @click="$emit(\'close\')">' +
    '<svg class="ov-icon" aria-hidden="true"><use href="#i-x"/></svg></button></div>' +
    '<div class="ov-dialog-body" :class="{\'ov-dialog-body-flush\': flush}" :id="uid + \'-body\'"><slot></slot></div>' +
    '<div class="ov-dialog-foot"><slot name="footer"></slot></div>' +
    '</div></div>',
  mounted() {
    this.opener = document.activeElement;
    scrollLock.lock();
    document.addEventListener('keydown', this.onKeydown, true);
    var box = this.$refs.box;
    var target = null;
    if (this.initialFocus === 'cancel') {
      target = box.querySelector('[data-dialog-cancel]');
    } else if (this.initialFocus === 'close') {
      target = box.querySelector('[data-dialog-close]');
    } else {
      target = box.querySelector('.ov-dialog-body input:not([type=hidden]):not([disabled]):not([readonly]), .ov-dialog-body textarea');
    }
    target = target || box.querySelector('[data-dialog-cancel], [data-dialog-close], button:not([disabled])');
    if (target) {
      target.focus();
    }
  },
  beforeUnmount() {
    document.removeEventListener('keydown', this.onKeydown, true);
  },
  unmounted() {
    scrollLock.unlock();
    var opener = this.opener;
    if (opener && opener.isConnected && typeof opener.focus === 'function') {
      opener.focus();
    }
  },
  methods: {
    // a click closes only when it started and ended on the backdrop itself
    // (a text selection that ends outside the dialog must not close it)
    onBackdropDown(event) {
      this.downOnBackdrop = event.target === event.currentTarget;
    },
    onBackdropClick(event) {
      var started = this.downOnBackdrop;
      this.downOnBackdrop = false;
      if (started && event.target === event.currentTarget && !this.busy) {
        this.$emit('close');
      }
    },
    focusables() {
      var nodes = this.$refs.box.querySelectorAll('button, input, textarea, select, a[href], [tabindex]');
      return Array.prototype.filter.call(nodes, function(el) {
        return !el.disabled && el.tabIndex >= 0 && el.offsetParent !== null;
      });
    },
    onKeydown(event) {
      if (event.key === 'Escape') {
        event.preventDefault();
        event.stopPropagation();
        if (!this.busy) {
          this.$emit('close');
        }
        return;
      }
      if (event.key !== 'Tab') {
        return;
      }
      var items = this.focusables();
      if (items.length === 0) {
        event.preventDefault();
        return;
      }
      var first = items[0];
      var last = items[items.length - 1];
      var active = document.activeElement;
      var inside = this.$refs.box.contains(active);
      if (!inside) {
        event.preventDefault();
        first.focus();
      } else if (event.shiftKey && active === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && active === last) {
        event.preventDefault();
        first.focus();
      }
    }
  }
};

// Password input with a Show/Hide toggle, label, help text and error.
var PasswordField = {
  props: {
    id: { type: String, required: true },
    label: { type: String, required: true },
    help: { type: String, default: '' },
    modelValue: { type: String, default: '' },
    error: { type: String, default: '' }
  },
  emits: ['update:modelValue'],
  data() {
    return { shown: false };
  },
  template: '<div class="ov-field">' +
    '<label class="ov-label" :for="id">{{ label }}</label>' +
    '<div class="ov-pw-row">' +
    '<input :id="id" class="ov-input" :type="shown ? \'text\' : \'password\'" :value="modelValue" ' +
    '@input="$emit(\'update:modelValue\', $event.target.value)" autocomplete="new-password" spellcheck="false" ' +
    ':aria-invalid="error ? \'true\' : null" :aria-describedby="id + \'-help\' + (error ? \' \' + id + \'-err\' : \'\')">' +
    '<button type="button" class="ov-btn" :aria-pressed="shown ? \'true\' : \'false\'" :aria-controls="id" @click="shown = !shown">{{ shown ? \'Hide\' : \'Show\' }}</button>' +
    '</div>' +
    '<div class="ov-help" :id="id + \'-help\'">{{ help }}</div>' +
    '<div class="ov-error" :id="id + \'-err\'" v-if="error">{{ error }}</div>' +
    '</div>'
};

// Action menu of a user row: bottom sheet on phones, popover anchored to the
// opener from 769 px (see style.css). role=menu, Up/Down/Home/End, Escape and
// a tap on the scrim close it, focus goes back to the opener.
// An item with a boolean `checked` is a radio item (role=menuitemradio,
// aria-checked, optional second line `sub`): the theme chooser uses them.
var AppMenu = {
  props: {
    title: { type: String, required: true },
    subtitle: { type: String, default: '' },
    items: { type: Array, required: true },
    anchor: { default: null },
    ariaLabel: { type: String, default: '' },
    // which item takes the focus on open: 'first' or the 'checked' one
    initialFocus: { type: String, default: 'first' }
  },
  emits: ['select', 'close'],
  data() {
    return { menuStyle: {} };
  },
  template: '<div class="ov-menu-layer">' +
    '<div class="ov-scrim" @click="$emit(\'close\')"></div>' +
    '<div class="ov-menu" role="menu" ref="menu" :aria-label="ariaLabel || (\'Actions for \' + title)" :style="menuStyle">' +
    '<div class="ov-menu-head"><p class="ov-menu-title">{{ title }}</p><span class="ov-small ov-muted" v-if="subtitle">{{ subtitle }}</span></div>' +
    '<ul class="ov-menu-list" role="none">' +
    '<template v-for="(item, index) in items" :key="item.id">' +
    '<li role="separator" class="ov-menu-sep" v-if="item.danger && index > 0 && !items[index - 1].danger"></li>' +
    '<li role="none"><button type="button" :role="typeof item.checked === \'boolean\' ? \'menuitemradio\' : \'menuitem\'" class="ov-menu-item" :class="{\'ov-menu-danger\': item.danger}" ' +
    ':aria-checked="typeof item.checked === \'boolean\' ? (item.checked ? \'true\' : \'false\') : null" ' +
    ':disabled="item.disabled" @click="$emit(\'select\', item)">' +
    '<svg class="ov-icon" aria-hidden="true"><use :href="\'#\' + item.icon"/></svg>' +
    '<template v-if="typeof item.checked === \'boolean\'"><span class="ov-menu-text">{{ item.label }}<span class="ov-menu-sub" v-if="item.sub">{{ item.sub }}</span></span>' +
    '<svg class="ov-icon ov-check" aria-hidden="true"><use href="#i-check"/></svg></template>' +
    '<template v-else>{{ item.label }}</template></button></li>' +
    '</template>' +
    '<li role="none"><button type="button" role="menuitem" class="ov-menu-item ov-menu-cancel" @click="$emit(\'close\')">Cancel</button></li>' +
    '</ul></div></div>',
  mounted() {
    scrollLock.lock();
    document.addEventListener('keydown', this.onKeydown, true);
    window.addEventListener('resize', this.position);
    this.position();
    var items = this.visibleItems();
    var first = items[0];
    if (this.initialFocus === 'checked') {
      first = items.filter(function(el) { return el.getAttribute('aria-checked') === 'true'; })[0] || first;
    }
    if (first) {
      first.focus();
    }
  },
  beforeUnmount() {
    document.removeEventListener('keydown', this.onKeydown, true);
    window.removeEventListener('resize', this.position);
  },
  unmounted() {
    scrollLock.unlock();
  },
  methods: {
    // popover position from 769 px (the sheet on phones ignores the variables)
    position() {
      if (!this.anchor || !this.anchor.getBoundingClientRect) {
        return;
      }
      var r = this.anchor.getBoundingClientRect();
      // measure against the fixed layer, not window.innerWidth: a classic scrollbar
      // (scrollbar-gutter: stable) would shift the popover by the scrollbar width
      var box = this.$el.querySelector('.ov-scrim').getBoundingClientRect();
      var menuH = this.$refs.menu ? this.$refs.menu.offsetHeight : 0;
      var top = r.bottom + 4;
      if (menuH && top + menuH > window.innerHeight - 8) {
        top = Math.max(8, r.top - 4 - menuH);
      }
      this.menuStyle = { '--menu-top': top + 'px', '--menu-right': Math.max(8, box.right - r.right) + 'px' };
    },
    visibleItems() {
      var nodes = this.$refs.menu.querySelectorAll('.ov-menu-item');
      return Array.prototype.filter.call(nodes, function(el) {
        return !el.disabled && el.offsetParent !== null;
      });
    },
    onKeydown(event) {
      var key = event.key;
      if (key === 'Escape') {
        event.preventDefault();
        event.stopPropagation();
        this.$emit('close');
        return;
      }
      if (['ArrowDown', 'ArrowUp', 'Home', 'End', 'Tab'].indexOf(key) === -1) {
        return;
      }
      var items = this.visibleItems();
      if (items.length === 0) {
        return;
      }
      event.preventDefault();
      var current = items.indexOf(document.activeElement);
      var next = current;
      if (key === 'Home') {
        next = 0;
      } else if (key === 'End') {
        next = items.length - 1;
      } else if (key === 'ArrowDown' || (key === 'Tab' && !event.shiftKey)) {
        next = current + 1 >= items.length ? 0 : current + 1;
      } else {
        next = current <= 0 ? items.length - 1 : current - 1;
      }
      items[next].focus();
    }
  }
};

// Theme: the inline script in index.html has already applied the saved choice
// (data-theme on <html>, color-scheme, meta theme-color) before the first paint.
// This is the same rule for later changes. localStorage["ovpn-theme"] holds
// light | dark | system; a blocked storage keeps the choice in memory only.
var THEME_KEY = 'ovpn-theme';
var THEME_LABELS = { light: 'Light', dark: 'Dark', system: 'System' };
var THEME_ICONS = { light: '#i-sun', dark: '#i-moon', system: '#i-monitor' };
var THEME_COLORS = { light: '#ffffff', dark: '#161b22' };
function validTheme(value) {
  return value === 'light' || value === 'dark' || value === 'system' ? value : 'system';
}
function readThemePref() {
  try {
    return validTheme(window.localStorage.getItem(THEME_KEY));
  } catch (e) {
    return validTheme(document.documentElement.getAttribute('data-theme-pref'));
  }
}
function applyTheme(resolved, pref) {
  var root = document.documentElement;
  root.setAttribute('data-theme', resolved);
  root.setAttribute('data-theme-pref', pref);
  root.style.colorScheme = resolved;
  var meta = document.querySelector('meta[name="theme-color"]');
  if (meta) {
    meta.setAttribute('content', THEME_COLORS[resolved]);
  }
}

// Centered state block of a list: loading skeleton, error, empty, no match.
var AppState = {
  props: {
    kind: { type: String, required: true },
    message: { type: String, default: '' },
    count: { type: Number, default: 3 },
    canAdd: { type: Boolean, default: false },
    checked: { type: String, default: '' },
    noun: { type: String, default: 'users' }
  },
  emits: ['retry', 'add', 'showall'],
  template: '<div class="ov-state-wrap">' +
    '<div v-if="kind == \'loading\'" role="status"><span class="visually-hidden">Loading {{ noun }}…</span>' +
    '<div class="ov-skel" v-for="n in count" :key="n" aria-hidden="true"></div></div>' +
    '<div v-else-if="kind == \'error\'" class="ov-state"><div class="ov-banner ov-banner-error" role="alert">{{ message }}</div>' +
    '<button type="button" class="ov-btn" @click="$emit(\'retry\')">Try again</button></div>' +
    '<div v-else-if="kind == \'empty\'" class="ov-state"><h3>{{ message }}</h3>' +
    '<span class="ov-muted ov-small" v-if="checked">{{ checked }}</span>' +
    '<button type="button" class="ov-btn ov-btn-primary" v-if="canAdd" @click="$emit(\'add\')">Add user</button></div>' +
    '<div v-else class="ov-state"><h3>{{ message }}</h3>' +
    '<button type="button" class="ov-btn" @click="$emit(\'showall\')">Show all users</button></div>' +
    '</div>'
};

const app = createApp({
  data() {
    return {
      columns: [
        {
          label: 'Name',
          field: 'Identity',
          sortFn: compareNames,
          thClass: 'c-name',
          tdClass: 'c-name',
        },
        {
          label: 'Status',
          field: '_rank',
          sortFn: compareValues,
          thClass: 'c-status',
          tdClass: 'c-status',
        },
        {
          label: 'Last login',
          field: '_loginTs',
          sortFn: compareValues,
          thClass: 'c-login',
          tdClass: 'c-login',
        },
        {
          label: 'Certificate expires',
          field: 'ExpirationDate',
          sortFn: compareDateStrings,
          thClass: 'c-exp',
          tdClass: 'c-exp',
        },
        {
          label: 'Actions',
          field: 'actions',
          sortable: false,
          thClass: 'c-actions',
          tdClass: 'c-actions',
        },
      ],
      rows: [],
      // order inside a group is the order on screen (History is always first
      // and is rendered separately). group 'danger' sits at the far right.
      actions: [
        { name: 'u-unrevoke', label: 'Unrevoke', icon: 'i-undo', group: 'routine', showWhenStatus: ['Revoked'], showForServerRole: ['master'], showForModule: ['core'] },
        { name: 'u-download-config', label: 'Download config', icon: 'i-download', group: 'routine', showWhenStatus: ['Active'], showForServerRole: ['master', 'slave'], showForModule: ['core'] },
        { name: 'u-edit-ccd', label: 'Edit routes', icon: 'i-route', group: 'routine', showWhenStatus: ['Active'], showForServerRole: ['master'], showForModule: ['ccd'] },
        { name: 'u-edit-ccd', label: 'Show routes', icon: 'i-route', group: 'routine', showWhenStatus: ['Active'], showForServerRole: ['slave'], showForModule: ['ccd'] },
        { name: 'u-change-password', label: 'Set password', icon: 'i-key', group: 'routine', showWhenStatus: ['Active'], showForServerRole: ['master'], showForModule: ['passwdAuth'] },
        { name: 'u-rotate', label: 'Rotate…', icon: 'i-rotate', group: 'routine', showWhenStatus: ['Revoked', 'Expired'], showForServerRole: ['master'], showForModule: ['core'] },
        { name: 'u-revoke', label: 'Revoke…', icon: 'i-ban', group: 'danger', showWhenStatus: ['Active'], showForServerRole: ['master'], showForModule: ['core'] },
        { name: 'u-delete', label: 'Delete…', icon: 'i-trash', group: 'danger', showWhenStatus: ['Revoked', 'Expired'], showForServerRole: ['master'], showForModule: ['core'] },
      ],
      filters: {
        hideRevoked: cookies.get('hideRevoked') == "true",
      },
      search: '',
      serverRole: "master",
      lastSync: "unknown",
      modulesEnabled: [],
      // user the current row action works with
      username: '',
      // table state
      loading: true,
      loadError: '',
      loaded: false,
      refreshing: false,
      updatedAt: null,
      // a refresh failed while rows are on screen: the message
      staleError: '',
      now: Date.now(),
      rowBusy: {},
      // the one open dialog: {kind: 'add'|'password'|'revoke'|'delete'|'rotate'|'config'|'routes'|'history', ...}
      dialog: null,
      notificationSpeed: (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) ? 0 : 900,
      // layout: cards up to 768 px, tables from 769 px
      isNarrow: window.matchMedia('(max-width: 768px)').matches,
      // 'users' | 'bans', mirrored in location.hash
      view: viewFromHash(),
      offline: typeof navigator.onLine === 'boolean' ? !navigator.onLine : false,
      // action menu of a row: {username, row key} or null (the opener element is kept out of the reactive state)
      menu: null,
      menuAnchor: null,
      // theme: light | dark | system, the OS preference, the chooser
      themePref: validTheme(document.documentElement.getAttribute('data-theme-pref')),
      osDark: !!(window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches),
      themeMenuOpen: false,
      themeAnchor: null,
      // banned IPs
      bans: [],
      bansLoaded: false,
      bansLoading: true,
      bansRefreshing: false,
      bansError: '',
      bansErrorNotFound: false,
      bansStaleError: '',
      bansUpdatedAt: null,
      bansFailures: 0,
      bansNow: Date.now(),
      bansAnnounce: '',
      bansQuiet: false,
      bansSearch: '',
    }
  },
  mounted: function () {
    this.loadUsers();
    this.getServerSetting();
    var _this = this;
    new MutationObserver(function() { _this.syncAriaSort(); })
      .observe(document.getElementById('app'), { subtree: true, childList: true, attributes: true, attributeFilter: ['class', 'aria-sort'] });

    // layout switch cards <-> table
    this.mql = window.matchMedia('(max-width: 768px)');
    this.onMql = function(event) { _this.isNarrow = event.matches; };
    if (this.mql.addEventListener) {
      this.mql.addEventListener('change', this.onMql);
    } else if (this.mql.addListener) {
      this.mql.addListener(this.onMql);
    }

    // theme: follow the OS while System is selected, and another tab's choice
    this.themeMql = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;
    this.onThemeMql = function(event) {
      _this.osDark = event.matches;
      _this.applyTheme();
    };
    this.onThemeStorage = function(event) {
      if (event.key === THEME_KEY || event.key === null) {
        _this.themePref = readThemePref();
        _this.applyTheme();
      }
    };
    if (this.themeMql) {
      if (this.themeMql.addEventListener) {
        this.themeMql.addEventListener('change', this.onThemeMql);
      } else if (this.themeMql.addListener) {
        this.themeMql.addListener(this.onThemeMql);
      }
    }
    window.addEventListener('storage', this.onThemeStorage);
    this.osDark = !!(this.themeMql && this.themeMql.matches);
    this.applyTheme();

    // view <-> hash, tab visibility and connectivity
    this.onHashChange = function() {
      var view = viewFromHash();
      if (view !== _this.view) {
        _this.view = view;
      }
    };
    this.onVisibility = function() {
      if (document.visibilityState === 'visible') {
        _this.bansNow = Date.now();
        _this.pollBans(true);
      } else {
        _this.stopBansTimer();
      }
    };
    this.onOnline = function() {
      _this.offline = false;
      _this.pollBans(true);
    };
    this.onOffline = function() {
      _this.offline = true;
      _this.stopBansTimer();
    };
    window.addEventListener('hashchange', this.onHashChange);
    document.addEventListener('visibilitychange', this.onVisibility);
    window.addEventListener('online', this.onOnline);
    window.addEventListener('offline', this.onOffline);

    // relative times of the ban list move on without a request
    this.nowTimer = setInterval(function() { _this.bansNow = Date.now(); }, BANS_POLL_MS);

    // the sticky header height: offset of the sticky table header and scroll-padding
    var header = this.$refs.header;
    if (header) {
      var setHeaderHeight = function() {
        document.documentElement.style.setProperty('--header-h', header.offsetHeight + 'px');
      };
      setHeaderHeight();
      if (window.ResizeObserver) {
        this.headerObserver = new ResizeObserver(setHeaderHeight);
        this.headerObserver.observe(header);
      }
    }

    // the count badge needs the ban list even when the Users view is open
    this.loadBans(true);
  },
  unmounted: function () {
    this.stopBansTimer();
    clearInterval(this.nowTimer);
    window.removeEventListener('hashchange', this.onHashChange);
    document.removeEventListener('visibilitychange', this.onVisibility);
    window.removeEventListener('online', this.onOnline);
    window.removeEventListener('offline', this.onOffline);
    window.removeEventListener('storage', this.onThemeStorage);
    if (this.themeMql && this.themeMql.removeEventListener) {
      this.themeMql.removeEventListener('change', this.onThemeMql);
    } else if (this.themeMql && this.themeMql.removeListener) {
      this.themeMql.removeListener(this.onThemeMql);
    }
    if (this.mql && this.mql.removeEventListener) {
      this.mql.removeEventListener('change', this.onMql);
    }
    if (this.headerObserver) {
      this.headerObserver.disconnect();
    }
  },
  watch: {
    view: function(view) {
      var hash = view === 'bans' ? '#bans' : '#users';
      if (window.location.hash !== hash) {
        window.history.replaceState(null, '', hash);
      }
      this.menu = null;
      if (view === 'bans') {
        this.bansNow = Date.now();
      }
      this.pollBans(true);
    },
  },
  computed: {
    ipv6Enabled: function () {
      return this.modulesEnabled.includes('ipv6')
    },
    // a static IPv6 address left over in the ccd is shown even when IPv6 is
    // disabled, so that it can be cleared
    showIPv6Address: function () {
      var ccd = this.dialog && this.dialog.ccd;
      if (!ccd) {
        return false;
      }
      return this.ipv6Enabled || (ccd.ClientAddressIPv6 != "" && ccd.ClientAddressIPv6 != "dynamic")
    },
    updatedTime: function() {
      return this.updatedAt ? formatClock(this.updatedAt) : '';
    },
    offsetLabel: function() {
      return offsetLabel();
    },
    hiddenCount: function() {
      return this.rows.length - this.hideFiltered(this.rows).length;
    },
    tableRows: function() {
      var nowMs = this.now;
      var query = this.search.trim().toLowerCase();
      return this.hideFiltered(this.rows).map(function(row) {
        return decorateRow(row, nowMs);
      }).filter(function(row) {
        if (query === '') {
          return true;
        }
        return [row.Identity, row._statusLabel, row.LastLoginIP].some(function(value) {
          return String(value || '').toLowerCase().indexOf(query) !== -1;
        });
      });
    },
    historyCountText: function() {
      var n = this.dialog && this.dialog.events ? this.dialog.events.length : 0;
      if (n >= HISTORY_LIMIT) {
        return 'Showing the latest ' + HISTORY_LIMIT + ' events.';
      }
      return plural(n, 'event');
    },
    // cards have no sortable header: same default order as the table (name)
    cardRows: function() {
      return this.tableRows.slice().sort(function(a, b) {
        return compareNames(a.Identity, b.Identity);
      });
    },
    // 'loading' | 'error' | 'empty' | 'nomatch' | 'rows'
    usersState: function() {
      if (this.loading) {
        return 'loading';
      }
      if (this.loadError) {
        return 'error';
      }
      if (this.rows.length == 0) {
        return 'empty';
      }
      return this.tableRows.length == 0 ? 'nomatch' : 'rows';
    },
    noMatchText: function() {
      var q = this.search.trim();
      return q ? 'No users match "' + q + '".' : 'No users match the filter.';
    },
    usersMeta: function() {
      if (this.refreshing) {
        return 'Refreshing…';
      }
      return this.updatedAt ? 'Updated ' + this.updatedTime + ' · ' + plural(this.rows.length, 'user') : '';
    },
    userCount: function() {
      return this.loaded ? String(this.rows.length) : '';
    },
    bansCount: function() {
      return this.bansLoaded ? this.bans.length : null;
    },
    bansTabLabel: function() {
      return this.bansLoaded ? 'Banned IPs, ' + plural(this.bans.length, 'active ban') : 'Banned IPs';
    },
    bansUpdatedClock: function() {
      return this.bansUpdatedAt ? formatClock(this.bansUpdatedAt) : '';
    },
    bansMeta: function() {
      if (this.bansRefreshing) {
        return 'Refreshing…';
      }
      if (!this.bansLoaded) {
        return '';
      }
      return this.bans.length + ' active · ' + (this.offline ? 'paused while offline' : 'auto-refresh 30 s') + ' · updated ' + this.bansUpdatedClock;
    },
    bansShowSearch: function() {
      return this.bans.length > BANS_SEARCH_MIN_ROWS;
    },
    // 'loading' | 'error' | 'empty' | 'rows'
    bansState: function() {
      if (!this.bansLoaded) {
        return this.bansError ? 'error' : 'loading';
      }
      return this.bans.length == 0 ? 'empty' : 'rows';
    },
    banRows: function() {
      var nowMs = this.bansNow;
      var query = this.bansShowSearch ? this.bansSearch.trim().toLowerCase() : '';
      return this.bans.filter(function(b) {
        return query === '' || (b.ip + ' ' + b.reason + ' ' + b.reasonLabel).toLowerCase().indexOf(query) !== -1;
      }).map(function(b) {
        return decorateBan(b, nowMs);
      });
    },
    bansErrorText: function() {
      var text = 'Could not load banned IPs: ' + this.bansError + '.';
      return this.bansErrorNotFound ? text + ' The ban list needs ovpn-admin v0.1.4 or later on the server.' : text;
    },
    menuRow: function() {
      var username = this.menu ? this.menu.username : null;
      var nowMs = this.now;
      var row = this.rows.find(function(r) { return r.Identity == username; });
      return row ? decorateRow(row, nowMs) : null;
    },
    menuItems: function() {
      var row = this.menuRow;
      if (!row) {
        return [];
      }
      var _this = this;
      var disabled = !!_this.rowBusy[row.Identity] || _this.offline;
      var items = [{ id: 'history', label: 'Login history', icon: 'i-history', danger: false, disabled: !!_this.rowBusy[row.Identity] }];
      ['routine', 'danger'].forEach(function(group) {
        _this.rowActions(row, group).forEach(function(action) {
          items.push({ id: action.name, label: action.label, icon: action.icon, danger: group == 'danger', disabled: disabled });
        });
      });
      return items;
    },
    menuSubtitle: function() {
      var row = this.menuRow;
      return row ? row._statusLabel + (row._statusNote ? ' · ' + row._statusNote : '') : '';
    },
    tzLabel: function() {
      return offsetLabel();
    },
    themeResolved: function() {
      return this.themePref === 'system' ? (this.osDark ? 'dark' : 'light') : this.themePref;
    },
    themeLabel: function() {
      return 'Theme: ' + THEME_LABELS[this.themePref] + (this.themePref === 'system' ? ' (' + THEME_LABELS[this.themeResolved] + ')' : '');
    },
    themeIcon: function() {
      return THEME_ICONS[this.themePref];
    },
    themeItems: function() {
      var pref = this.themePref;
      return [
        { id: 'light', label: THEME_LABELS.light, icon: 'i-sun', checked: pref === 'light' },
        { id: 'dark', label: THEME_LABELS.dark, icon: 'i-moon', checked: pref === 'dark' },
        { id: 'system', label: THEME_LABELS.system, icon: 'i-monitor', checked: pref === 'system',
          sub: 'Follows this device, now ' + (this.osDark ? THEME_LABELS.dark : THEME_LABELS.light) }
      ];
    },
  },
  methods: {
    // ---- layout, views, menu ----
    focusMain: function() {
      var main = document.getElementById('main');
      if (main) {
        main.focus();
      }
    },
    refreshView: function() {
      if (this.view == 'bans') {
        this.loadBans(false);
      } else {
        this.loadUsers();
      }
    },
    primaryAction: function(row) {
      return this.rowActions(row, 'routine')[0] || null;
    },
    hasMore: function(row) {
      return this.rowActions(row, 'routine').length + this.rowActions(row, 'danger').length > 0;
    },
    rowLocked: function(row) {
      return !!this.rowBusy[row.Identity] || this.offline;
    },
    openMenu: function(row, event) {
      this.menuAnchor = markRaw(event.currentTarget);
      this.menu = { username: row.Identity };
    },
    closeMenu: function() {
      var anchor = this.menuAnchor;
      this.menu = null;
      if (anchor && anchor.isConnected) {
        anchor.focus();
      }
    },
    // The menu closes first and focus goes back to its opener, so that a
    // dialog opened by the action returns focus to the same button.
    selectMenuItem: function(item) {
      var _this = this;
      var username = _this.menu ? _this.menu.username : '';
      var anchor = _this.menuAnchor;
      _this.menu = null;
      if (anchor && anchor.isConnected) {
        anchor.focus();
      }
      _this.$nextTick(function() {
        if (item.id == 'history') {
          _this.openHistory(username);
        } else {
          _this.rowActionFn(item.id, username);
        }
      });
    },
    iconFor: function(action) {
      return '#' + action.icon;
    },

    // ---- theme ----
    applyTheme: function() {
      applyTheme(this.themeResolved, this.themePref);
    },
    openThemeMenu: function() {
      if (this.themeMenuOpen || this.menu || this.dialog) {
        return;
      }
      this.themeAnchor = markRaw(this.$refs.themeBtn);
      this.themeMenuOpen = true;
    },
    toggleThemeMenu: function() {
      if (this.themeMenuOpen) {
        this.closeThemeMenu();
      } else {
        this.openThemeMenu();
      }
    },
    closeThemeMenu: function() {
      this.themeMenuOpen = false;
      var anchor = this.themeAnchor;
      if (anchor && anchor.isConnected) {
        anchor.focus();
      }
    },
    setTheme: function(pref) {
      this.themePref = validTheme(pref);
      try {
        window.localStorage.setItem(THEME_KEY, this.themePref);
      } catch (e) {
        // blocked storage (private mode): the choice lasts until the page closes
      }
      this.applyTheme();
      this.closeThemeMenu();
    },

    // ---- banned IPs ----
    pollingAllowed: function() {
      return document.visibilityState !== 'hidden' && !this.offline;
    },
    stopBansTimer: function() {
      if (this.bansTimer) {
        clearTimeout(this.bansTimer);
        this.bansTimer = null;
      }
    },
    // 30 s while the Bans view is open (120 s after 3 failures in a row),
    // 60 s to keep the count badge current while the Users view is open
    scheduleBans: function() {
      var _this = this;
      _this.stopBansTimer();
      if (!_this.pollingAllowed()) {
        return;
      }
      var delay = BANS_COUNT_POLL_MS;
      if (_this.view == 'bans') {
        delay = _this.bansFailures >= BANS_BACKOFF_AFTER ? BANS_POLL_BACKOFF_MS : BANS_POLL_MS;
      }
      _this.bansTimer = setTimeout(function() { _this.pollBans(); }, delay);
    },
    pollBans: function() {
      this.stopBansTimer();
      if (this.pollingAllowed()) {
        this.loadBans(true);
      }
    },
    // one request at a time; the next poll is scheduled when it ends
    loadBans: function(background) {
      var _this = this;
      if (_this.bansPromise) {
        return _this.bansPromise;
      }
      _this.stopBansTimer();
      _this.bansRefreshing = !background || !_this.bansLoaded;
      if (!_this.bansLoaded) {
        _this.bansLoading = true;
        _this.bansError = '';
      }
      _this.bansPromise = axios.request(axios_cfg('api/bans'))
        .then(function(response) {
          var data = response.data;
          var list = Array.isArray(data) ? data : (data && Array.isArray(data.bans) ? data.bans : null);
          if (list === null) {
            throw new Error('unexpected response');
          }
          var bans = list.map(normalizeBan).filter(function(b) { return b.ip !== ''; }).sort(function(a, b) {
            return b.bannedMs - a.bannedMs;
          });
          var previous = _this.bansLoaded ? _this.bans.length : null;
          _this.bans = bans;
          _this.bansLoaded = true;
          _this.bansUpdatedAt = new Date();
          _this.bansNow = Date.now();
          _this.bansFailures = 0;
          _this.bansError = '';
          _this.bansStaleError = '';
          // announced only when the count changes: silent polls do not chatter
          if (previous !== null && previous !== bans.length && !_this.bansQuiet) {
            _this.bansAnnounce = plural(bans.length, 'active ban');
          }
        })
        .catch(function(error) {
          _this.bansFailures++;
          var message = trimPeriod(errorMessage(error));
          if (_this.bansLoaded) {
            _this.bansStaleError = message;
          } else {
            _this.bansError = message;
            _this.bansErrorNotFound = !!(error.response && error.response.status === 404);
          }
        })
        .then(function() {
          _this.bansLoading = false;
          _this.bansRefreshing = false;
          _this.bansPromise = null;
          _this.scheduleBans();
        });
      return _this.bansPromise;
    },

    // vue-good-table-next marks every unsorted column aria-sort="descending";
    // only the column that is sorted may carry the attribute.
    syncAriaSort: function() {
      document.querySelectorAll('table.ov-users').forEach(function(table) {
        if (!table.hasAttribute('aria-label')) {
          table.setAttribute('aria-label', 'Users');
        }
      });
      document.querySelectorAll('.ov-users thead th').forEach(function(th) {
        var asc = th.classList.contains('sorting-asc');
        var desc = th.classList.contains('sorting-desc');
        var want = asc ? 'ascending' : (desc ? 'descending' : null);
        if (th.getAttribute('aria-sort') !== want) {
          if (want) {
            th.setAttribute('aria-sort', want);
          } else {
            th.removeAttribute('aria-sort');
          }
        }
      });
    },
    hideFiltered: function(rows) {
      if (!this.filters.hideRevoked) {
        return rows;
      }
      return rows.filter(function(account) {
        return account.AccountStatus == "Active"
      });
    },
    setHideRevoked: function(checked) {
      this.filters.hideRevoked = checked;
      cookies.set('hideRevoked', checked);
    },
    showAllUsers: function() {
      this.search = '';
      this.setHideRevoked(false);
    },
    toast: function(type, title, text) {
      // errors stay until dismissed, successes go after 5 s
      this.$notify({ title: title, text: text || '', type: type, duration: type == 'error' ? -1 : 5000 });
    },
    rowActions: function(row, group) {
      var _this = this;
      return _this.actions.filter(function(action) {
        return action.group == group &&
          action.showWhenStatus.includes(row.AccountStatus) &&
          action.showForServerRole.includes(_this.serverRole) &&
          action.showForModule.some(function(p) { return _this.modulesEnabled.includes(p) });
      });
    },
    actionAriaLabel: function(action, username) {
      return action.label.replace(/…$/, '') + ' ' + username;
    },
    rowActionFn: function(actionName, username) {
      var handlers = {
        'u-revoke': this.openRevoke,
        'u-unrevoke': this.unrevokeUserAction,
        'u-rotate': this.openRotate,
        'u-delete': this.openDelete,
        'u-show-config': this.showConfigAction,
        'u-download-config': this.downloadConfigAction,
        'u-edit-ccd': this.editCcdAction,
        'u-disconnect-user': this.disconnectUserAction,
        'u-change-password': this.openChangePassword,
      };
      var handler = handlers[actionName];
      if (!handler) {
        console.error('unknown row action: ' + actionName);
        return;
      }
      this.username = username;
      handler();
    },

    // ---- dialogs ----
    closeDialog: function() {
      var d = this.dialog;
      if (d && d.busy) {
        return;
      }
      this.dialog = null;
      if (this.view == 'bans') {
        this.focusAfterBans();
        return;
      }
      this.focusAfterReload(d ? d.username : '');
    },
    // after a Banned IPs dialog: the opener keeps focus; when its row is gone, Ban IP gets it
    focusAfterBans: function() {
      this.$nextTick(function() {
        var active = document.activeElement;
        if (active && active !== document.body && active.isConnected) {
          return;
        }
        var target = document.getElementById('ban-add-btn') || document.getElementById('add-user-btn');
        if (target) {
          target.focus();
        }
      });
    },
    // The row list reloads after most actions; when the opener is gone, focus
    // goes to the row's History button, or to Add user when the row is gone.
    focusAfterReload: function(username, afterDelete) {
      var _this = this;
      _this.$nextTick(function() {
        var active = document.activeElement;
        if (active && active !== document.body && active.isConnected) {
          return;
        }
        var target = null;
        if (username && !afterDelete) {
          target = document.querySelector('[data-history-for="' + String(username).replace(/["\\]/g, '\\$&') + '"]');
        }
        target = target || document.getElementById('add-user-btn');
        if (target) {
          target.focus();
        }
      });
    },
    fieldError: function(name) {
      var d = this.dialog;
      if (!d || !d.submitted) {
        return '';
      }
      if (name == 'ban-ip') {
        return validateBanIp(d.ip);
      }
      if (name == 'ban-note') {
        return validateBanNote(d.note);
      }
      if (name == 'username') {
        return validateUsername(d.username);
      }
      return validatePassword(d.password);
    },
    actionError: function(verb, message) {
      return 'Could not ' + verb + ' ' + this.dialog.username + ': ' + trimPeriod(message) + '.';
    },

    openAddUser: function() {
      this.dialog = { kind: 'add', username: '', password: '', submitted: false, busy: false, error: '' };
    },
    openChangePassword: function() {
      this.dialog = { kind: 'password', username: this.username, password: '', submitted: false, busy: false, error: '' };
    },
    openRotate: function() {
      this.dialog = { kind: 'rotate', username: this.username, password: '', submitted: false, busy: false, error: '' };
    },
    openDelete: function() {
      this.dialog = { kind: 'delete', username: this.username, busy: false, error: '' };
    },
    openRevoke: function() {
      var _this = this;
      var username = _this.username;
      var token = ++dialogCounter;
      _this.dialog = { kind: 'revoke', username: username, busy: false, error: '', checking: true, sessions: null, token: token };
      _this.fetchUsers().then(function(rows) {
        if (!_this.dialog || _this.dialog.token !== token) {
          return;
        }
        var row = rows.find(function(r) { return r.Identity == username; });
        _this.dialog.sessions = !row ? null : (row.ConnectionStatus == 'Connected' ? Math.max(1, Number(row.Connections) || 0) : 0);
        _this.dialog.checking = false;
      }).catch(function() {
        if (_this.dialog && _this.dialog.token === token) {
          _this.dialog.sessions = null;
          _this.dialog.checking = false;
        }
      });
    },

    // ---- manual ban and unban (Banned IPs view, master only) ----
    openBanAdd: function() {
      this.dialog = { kind: 'ban-add', ip: '', note: '', submitted: false, busy: false, error: '' };
    },
    openUnban: function(ban) {
      this.dialog = { kind: 'unban', ip: ban.ip, permanent: !!ban.permanent, busy: false, error: '' };
    },
    banForm: function(ip, note) {
      var data = new URLSearchParams();
      data.append('ip', ip);
      if (note) {
        data.append('reason', note);
      }
      return data;
    },
    // reloads the list after a change, also when a poll is already running (its answer may predate the change)
    reloadBans: function() {
      var _this = this;
      var running = _this.bansPromise;
      if (running) {
        return running.then(function() { return _this.loadBans(false); });
      }
      return _this.loadBans(false);
    },
    // one request: busy state, no double submit, inline error, toast and list reload on success
    runBanRequest: function(url, form, verb, onSuccess) {
      var _this = this;
      var d = _this.dialog;
      if (!d || d.busy) {
        return;
      }
      d.busy = true;
      d.error = '';
      axios.request(axios_cfg(url, form, 'form'))
      .then(function() {
        _this.dialog = null;
        var message = onSuccess(d);
        _this.focusAfterBans();
        // the count change that follows must not replace the result in the live region
        _this.bansQuiet = true;
        return _this.reloadBans().then(function() {
          _this.bansQuiet = false;
          _this.bansAnnounce = message + '. ' + plural(_this.bans.length, 'active ban') + '.';
          // an unbanned row is gone now: focus must not fall back to the page
          _this.focusAfterBans();
        });
      })
      .catch(function(error) {
        // a failed reload after a successful change is shown by the list itself; this branch is for the request
        if (_this.dialog === d) {
          d.busy = false;
          d.error = 'Could not ' + verb + ' ' + d.ip + ': ' + trimPeriod(errorMessage(error)) + '.';
        }
      });
    },
    submitBanAdd: function() {
      var _this = this;
      var d = _this.dialog;
      d.submitted = true;
      if (validateBanIp(d.ip) || validateBanNote(d.note)) {
        return;
      }
      var ip = d.ip.trim();
      d.ip = ip;
      _this.runBanRequest('api/ban/manual', _this.banForm(ip, d.note.trim()), 'ban', function() {
        _this.toast('success', ip + ' banned', 'The ban is permanent until you unban it.');
        return ip + ' banned permanently';
      });
    },
    submitUnban: function() {
      var _this = this;
      var d = _this.dialog;
      _this.runBanRequest('api/unban', _this.banForm(d.ip), 'unban', function() {
        _this.toast('success', d.ip + ' unbanned', 'It can connect again.');
        return d.ip + ' unbanned';
      });
    },

    // runs one confirmed dialog request: busy state, no double submit,
    // inline error, close and reload on success
    submitDialog: function(verb, request, onSuccess, afterDelete) {
      var _this = this;
      var d = _this.dialog;
      if (!d || d.busy) {
        return;
      }
      d.busy = true;
      d.error = '';
      request()
      .then(function(response) {
        _this.dialog = null;
        onSuccess(d, response);
        _this.loadUsers();
        _this.focusAfterReload(d.username, afterDelete);
      })
      .catch(function(error) {
        d.busy = false;
        d.error = _this.actionError(verb, errorMessage(error));
      });
    },
    userForm: function(username, password) {
      var data = new URLSearchParams();
      data.append('username', username);
      if (password !== undefined) {
        data.append('password', password);
      }
      return data;
    },
    revokeUser: function() {
      var _this = this;
      var d = _this.dialog;
      var sessions = d.sessions > 0 ? d.sessions : 0;
      _this.submitDialog('revoke', function() {
        return axios.request(axios_cfg('api/user/revoke', _this.userForm(d.username), 'form'));
      }, function() {
        _this.toast('success', d.username + ' revoked', sessions > 0 ? plural(sessions, 'session') + ' disconnected.' : '');
      });
    },
    deleteUser: function() {
      var _this = this;
      var d = _this.dialog;
      _this.submitDialog('delete', function() {
        return axios.request(axios_cfg('api/user/delete', _this.userForm(d.username), 'form'));
      }, function() {
        _this.toast('success', d.username + ' deleted');
      }, true);
    },
    rotateUser: function() {
      var _this = this;
      var d = _this.dialog;
      var needPassword = _this.modulesEnabled.includes('passwdAuth');
      d.submitted = true;
      if (needPassword && validatePassword(d.password)) {
        return;
      }
      _this.submitDialog('rotate certificate for', function() {
        return axios.request(axios_cfg('api/user/rotate', _this.userForm(d.username, needPassword ? d.password : ''), 'form'));
      }, function() {
        _this.toast('success', 'New certificate issued for ' + d.username, 'Download the new config and send it to ' + d.username + '.');
      });
    },
    changeUserPassword: function() {
      var _this = this;
      var d = _this.dialog;
      d.submitted = true;
      if (validatePassword(d.password)) {
        return;
      }
      _this.submitDialog('set password for', function() {
        return axios.request(axios_cfg('api/user/change-password', _this.userForm(d.username, d.password), 'form'));
      }, function() {
        _this.toast('success', 'Password set for ' + d.username);
      });
    },
    createUser: function() {
      var _this = this;
      var d = _this.dialog;
      var needPassword = _this.modulesEnabled.includes('passwdAuth');
      d.submitted = true;
      if (validateUsername(d.username) || (needPassword && validatePassword(d.password))) {
        return;
      }
      _this.submitDialog('create', function() {
        return axios.request(axios_cfg('api/user/create', _this.userForm(d.username, needPassword ? d.password : ''), 'form'));
      }, function() {
        _this.toast('success', d.username + ' created', "Download the config from the user's row.");
      });
    },

    unrevokeUserAction: function() {
      var _this = this;
      var username = _this.username;
      if (_this.rowBusy[username]) {
        return;
      }
      _this.rowBusy = Object.assign({}, _this.rowBusy, { [username]: true });
      axios.request(axios_cfg('api/user/unrevoke', _this.userForm(username), 'form'))
      .then(function(response) {
        _this.toast('success', username + ' restored', 'The existing config file works again.');
        return _this.loadUsers();
      })
      .catch(function(error) {
        _this.toast('error', 'Could not restore ' + username, errorMessage(error));
      })
      .then(function() {
        var busy = Object.assign({}, _this.rowBusy);
        delete busy[username];
        _this.rowBusy = busy;
        _this.focusAfterReload(username);
      });
    },
    showConfigAction: function() {
      var _this = this;
      var username = _this.username;
      _this.dialog = { kind: 'config', username: username, text: '' };
      axios.request(axios_cfg('api/user/config/show', _this.userForm(username), 'form'))
      .then(function(response) {
        if (_this.dialog && _this.dialog.kind == 'config' && _this.dialog.username == username) {
          _this.dialog.text = response.data;
        }
      })
      .catch(function(error) {
        _this.dialog = null;
        _this.toast('error', 'Could not show config for ' + username, errorMessage(error));
      });
    },
    downloadConfigAction: function() {
      var _this = this;
      var username = _this.username;
      axios.request(axios_cfg('api/user/config/show', _this.userForm(username), 'form'))
      .then(function(response) {
        const blob = new Blob([response.data], { type: 'text/plain' })
        const link = document.createElement('a')
        link.href = URL.createObjectURL(blob)
        link.download = username + ".ovpn"
        link.click()
        URL.revokeObjectURL(link.href)
      }).catch(function(error) {
        _this.toast('error', 'Could not download config for ' + username, errorMessage(error));
      });
    },
    editCcdAction: function() {
      var _this = this;
      var username = _this.username;
      var d = { kind: 'routes', username: username, ccd: emptyCcd(), loaded: false, newRoute: emptyRoute(), busy: false, error: '' };
      _this.dialog = d;
      axios.request(axios_cfg('api/user/ccd', _this.userForm(username), 'form'))
      .then(function(response) {
        if (_this.dialog && _this.dialog.kind == 'routes' && _this.dialog.username == username) {
          _this.dialog.ccd = normalizeCcd(response.data, username);
          _this.dialog.loaded = true;
        }
      })
      .catch(function(error) {
        if (_this.dialog && _this.dialog.kind == 'routes' && _this.dialog.username == username) {
          _this.dialog.error = 'Could not load routes for ' + username + ': ' + trimPeriod(errorMessage(error)) + '.';
        }
      });
    },
    disconnectUserAction: function() {
      axios.request(axios_cfg('api/user/disconnect', this.userForm(this.username), 'form'))
      .then(function(response) {
        console.log(response.data);
      });
    },

    copyConfig: function() {
      var _this = this;
      copyToClipboard(_this.dialog.text)
      .then(function() {
        _this.toast('success', 'Config copied to clipboard');
      })
      .catch(function(error) {
        _this.toast('error', 'Could not copy the config', errorMessage(error));
      });
    },

    addRoute: function() {
      var route = this.dialog.newRoute;
      if (route.Address.trim() == '') {
        return;
      }
      this.dialog.ccd.CustomRoutes.push({
        Address: route.Address.trim(),
        Mask: route.Mask.trim(),
        Description: route.Description
      });
      this.dialog.newRoute = emptyRoute();
    },

    ccdApply: function() {
      var _this = this;
      var d = _this.dialog;
      if (!d.loaded || d.busy) {
        return;
      }
      // a route typed in the "new route" row but not added is still saved
      _this.addRoute();
      var ccd = {
        User: d.ccd.User,
        ClientAddress: d.ccd.ClientAddress.trim() || 'dynamic',
        ClientAddressIPv6: d.ccd.ClientAddressIPv6.trim() || 'dynamic',
        CustomRoutes: d.ccd.CustomRoutes
      };
      _this.submitDialog('save routes for', function() {
        return axios.request(axios_cfg('api/user/ccd/apply', JSON.stringify(ccd), 'json'));
      }, function() {
        _this.toast('success', 'Routes saved for ' + d.username);
      });
    },

    // ---- login history ----
    openHistory: function(username) {
      this.dialog = { kind: 'history', username: username, status: 'loading', refreshing: false, events: [], error: '', token: ++dialogCounter };
      this.loadHistory();
    },
    loadHistory: function(refresh) {
      var _this = this;
      var d = _this.dialog;
      if (!d || d.kind != 'history') {
        return;
      }
      var token = d.token = ++dialogCounter;
      var username = d.username;
      if (refresh) {
        d.refreshing = true;
      } else {
        d.status = 'loading';
        d.events = [];
        d.error = '';
      }
      axios.request(axios_cfg('api/user/audit?username=' + encodeURIComponent(username) + '&limit=' + HISTORY_LIMIT))
      .then(function(response) {
        if (!_this.dialog || _this.dialog.token !== token) {
          return;
        }
        var events = response.data && Array.isArray(response.data.events) ? response.data.events : [];
        _this.dialog.events = events;
        _this.dialog.status = 'loaded';
        _this.dialog.refreshing = false;
      })
      .catch(function(error) {
        if (!_this.dialog || _this.dialog.token !== token) {
          return;
        }
        _this.dialog.refreshing = false;
        if (refresh && _this.dialog.status == 'loaded') {
          // keep the table that is on screen, say why it did not refresh
          _this.toast('error', 'Could not refresh login history', errorMessage(error));
          return;
        }
        _this.dialog.error = trimPeriod(errorMessage(error));
        _this.dialog.status = 'error';
      });
    },
    eventLabel: function(ev) {
      return EVENT_LABELS[ev.Event] || ev.Event;
    },
    eventClass: function(ev) {
      return {
        'ov-ev-connect': ev.Event == 'connect',
        'ov-ev-fail': ev.Event == 'auth_fail'
      };
    },
    eventTimeLocal: function(ev) {
      var d = new Date(ev.Time);
      return isNaN(d.getTime()) ? String(ev.Time || '') : formatLocal(d, true);
    },
    eventTimeUtc: function(ev) {
      var d = new Date(ev.Time);
      return isNaN(d.getTime()) ? '' : formatUtcSeconds(d);
    },
    formatBytes: formatBytes,

    // ---- user list and settings ----
    fetchUsers: function() {
      return axios.request(axios_cfg('api/users/list'))
        .then(function(response) {
          return Array.isArray(response.data) ? response.data : [];
        });
    },
    loadUsers: function() {
      var _this = this;
      _this.refreshing = true;
      if (!_this.loaded) {
        _this.loading = true;
        _this.loadError = '';
      }
      // the Banned IPs count follows every user list load
      _this.loadBans(true);
      return _this.fetchUsers()
        .then(function(rows) {
          _this.rows = rows;
          _this.now = Date.now();
          _this.updatedAt = new Date();
          _this.loaded = true;
          _this.loadError = '';
          _this.staleError = '';
        })
        .catch(function(error) {
          if (_this.loaded) {
            // rows are on screen: keep them, say why they are old
            _this.staleError = trimPeriod(errorMessage(error));
          } else {
            _this.loadError = trimPeriod(errorMessage(error));
          }
        })
        .then(function() {
          _this.loading = false;
          _this.refreshing = false;
        });
    },

    getServerSetting: function() {
      var _this = this;
      axios.request(axios_cfg('api/server/settings'))
      .then(function(response) {
        _this.serverRole = response.data.serverRole;
        _this.modulesEnabled = Array.isArray(response.data.modules) ? response.data.modules : [];

        if (_this.serverRole == "slave") {
          axios.request(axios_cfg('api/sync/last/successful'))
          .then(function(response) {
            _this.lastSync =  response.data;
          });
        }
      })
      .catch(function(error) {
        _this.toast('error', 'Could not load server settings', 'Row actions are hidden until this loads. Reload the page to retry.');
      });
    },
  }

});

app.component('app-dialog', AppDialog);
app.component('app-menu', AppMenu);
app.component('app-state', AppState);
app.component('password-field', PasswordField);
app.use(Notifications);
app.use(VueGoodTablePlugin);
app.mount('#app');
