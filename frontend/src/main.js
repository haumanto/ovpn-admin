import { createApp } from 'vue';
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
  return pad2(date.getHours()) + ':' + pad2(date.getMinutes()) + ':' + pad2(date.getSeconds());
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
  if (online) {
    badgeClass = 'ov-badge-online';
    note = plural(Math.max(1, Number(row.Connections) || 0), 'session');
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
  return Array.from(password).length < 6 ? 'Use at least 6 characters.' : '';
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
  template: '<div class="ov-backdrop">' +
    '<div class="ov-dialog" :class="\'ov-dialog-\' + size" role="dialog" aria-modal="true" ref="box" ' +
    ':aria-labelledby="uid + \'-title\'" :aria-describedby="describeBody ? uid + \'-body\' : null">' +
    '<div class="ov-dialog-head"><h2 class="ov-dialog-title" :id="uid + \'-title\'">{{ title }}</h2>' +
    '<p class="ov-dialog-meta" v-if="$slots.meta"><slot name="meta"></slot></p></div>' +
    '<div class="ov-dialog-body" :class="{\'ov-dialog-body-flush\': flush}" :id="uid + \'-body\'"><slot></slot></div>' +
    '<div class="ov-dialog-foot"><slot name="footer"></slot></div>' +
    '</div></div>',
  mounted() {
    this.opener = document.activeElement;
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
    var opener = this.opener;
    if (opener && opener.isConnected && typeof opener.focus === 'function') {
      opener.focus();
    }
  },
  methods: {
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
      // Order inside a group is the order on screen (History is always first
      // and is rendered separately). group 'danger' sits at the far right.
      actions: [
        { name: 'u-unrevoke', label: 'Unrevoke', group: 'routine', showWhenStatus: ['Revoked'], showForServerRole: ['master'], showForModule: ['core'] },
        { name: 'u-download-config', label: 'Download config', group: 'routine', showWhenStatus: ['Active'], showForServerRole: ['master', 'slave'], showForModule: ['core'] },
        { name: 'u-edit-ccd', label: 'Edit routes', group: 'routine', showWhenStatus: ['Active'], showForServerRole: ['master'], showForModule: ['ccd'] },
        { name: 'u-edit-ccd', label: 'Show routes', group: 'routine', showWhenStatus: ['Active'], showForServerRole: ['slave'], showForModule: ['ccd'] },
        { name: 'u-change-password', label: 'Set password', group: 'routine', showWhenStatus: ['Active'], showForServerRole: ['master'], showForModule: ['passwdAuth'] },
        { name: 'u-rotate', label: 'Rotate…', group: 'routine', showWhenStatus: ['Revoked', 'Expired'], showForServerRole: ['master'], showForModule: ['core'] },
        { name: 'u-revoke', label: 'Revoke…', group: 'danger', showWhenStatus: ['Active'], showForServerRole: ['master'], showForModule: ['core'] },
        { name: 'u-delete', label: 'Delete…', group: 'danger', showWhenStatus: ['Revoked', 'Expired'], showForServerRole: ['master'], showForModule: ['core'] },
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
      now: Date.now(),
      rowBusy: {},
      // the one open dialog: {kind: 'add'|'password'|'revoke'|'delete'|'rotate'|'config'|'routes'|'history', ...}
      dialog: null,
      notificationSpeed: (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) ? 0 : 900,
    }
  },
  mounted: function () {
    this.loadUsers();
    this.getServerSetting();
    var _this = this;
    new MutationObserver(function() { _this.syncAriaSort(); })
      .observe(document.getElementById('app'), { subtree: true, childList: true, attributes: true, attributeFilter: ['class', 'aria-sort'] });
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
  },
  methods: {
    // vue-good-table-next marks every unsorted column aria-sort="descending";
    // only the column that is sorted may carry the attribute.
    syncAriaSort: function() {
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
      this.focusAfterReload(d ? d.username : '');
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
      return _this.fetchUsers()
        .then(function(rows) {
          _this.rows = rows;
          _this.now = Date.now();
          _this.updatedAt = new Date();
          _this.loaded = true;
          _this.loadError = '';
        })
        .catch(function(error) {
          if (_this.loaded) {
            // rows are on screen: keep them
            _this.toast('error', 'Could not refresh the user list', errorMessage(error));
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
app.component('password-field', PasswordField);
app.use(Notifications);
app.use(VueGoodTablePlugin);
app.mount('#app');
