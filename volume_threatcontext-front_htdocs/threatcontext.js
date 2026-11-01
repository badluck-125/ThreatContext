/* ThreatContext — shared presentation-tier script.
 *
 * Two behaviours, both data-attribute driven so every page stays
 * plain HTML:
 *
 *  - entry forms:   <form data-entry-endpoint="<api endpoint>">
 *      collects the fields, converts them to one JSON object and
 *      POSTs it to /api/index.php/<endpoint> (front-tier proxy).
 *      Optional data-field-map='{"form_name":"api_name"}' renames
 *      fields (e.g. the home page maps cve_id -> request).
 *
 *  - consult forms: <form data-consult-endpoint="<api endpoint>"
 *                        data-record-key="<key of the record in the response>">
 *      GETs /api/index.php/<endpoint>?<fields> and renders each
 *      returned record as a two-column table.
 */

(function () {
    'use strict';

    var API_BASE = '/api/index.php/';

    function $(id) { return document.getElementById(id); }

    function setStatus(el, text, kind) {
        el.textContent = text;
        el.className = 'status-message' + (kind ? ' ' + kind : '');
    }

    /* fetch wrapper: always resolves with {ok, status, data} */
    function api(path, options) {
        return fetch(API_BASE + path, options).then(function (resp) {
            return resp.json().then(function (data) {
                return { ok: resp.ok, status: resp.status, data: data };
            });
        });
    }

    /* ---- rendering helpers ---- */

    function jsonBox(data) {
        var pre = document.createElement('pre');
        pre.className = 'json-box';
        pre.textContent = JSON.stringify(data, null, 2);
        return pre;
    }

    function recordTable(record) {
        var table = document.createElement('table');
        table.className = 'record-table';
        Object.keys(record).forEach(function (key) {
            var tr = document.createElement('tr');
            var th = document.createElement('th');
            th.textContent = key;
            var td = document.createElement('td');
            var value = record[key];
            if (value !== null && typeof value === 'object') {
                td.appendChild(jsonBox(value));
            } else {
                td.textContent = (value === null || value === undefined) ? '' : String(value);
                if (typeof value === 'string' && value.length > 120) {
                    td.className = 'wrap';
                }
            }
            tr.appendChild(th);
            tr.appendChild(td);
            table.appendChild(tr);
        });
        return table;
    }

    function collectPayload(form) {
        var map = {};
        try { map = JSON.parse(form.dataset.fieldMap || '{}'); } catch (e) { /* keep {} */ }
        var payload = {};
        new FormData(form).forEach(function (value, key) {
            if (value === '') { return; }                 // omit empty optional fields
            var target = map[key] || key;                 // optional field rename
            payload[target] = value;
        });
        ['exploit_id', 'ioc_id'].forEach(function (f) {   // numeric identifiers
            if (payload[f] !== undefined) { payload[f] = parseInt(payload[f], 10); }
        });
        return payload;
    }

    /* ---- entry forms ---- */

    function wireEntryForm(form) {
        var status = $('status-message');
        var result = $('result');
        var button = form.querySelector('button[type="submit"]');

        form.addEventListener('submit', function (e) {
            e.preventDefault();
            result.innerHTML = '';
            var payload = collectPayload(form);

            // point_of_interest must be typed as JSON text
            if (payload.point_of_interest !== undefined) {
                try {
                    payload.point_of_interest = JSON.parse(payload.point_of_interest);
                } catch (err) {
                    setStatus(status, 'point_of_interest is not valid JSON: ' + err.message, 'error');
                    return;
                }
            }

            setStatus(status, 'Sending...', '');
            button.disabled = true;

            api(form.dataset.entryEndpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            }).then(function (r) {
                setStatus(status, r.ok ? 'Saved (HTTP ' + r.status + ')' : 'Error (HTTP ' + r.status + ')', r.ok ? 'success' : 'error');
                result.appendChild(jsonBox(r.data));
            }).catch(function (err) {
                setStatus(status, 'Could not reach the application tier: ' + err.message, 'error');
            }).finally(function () {
                button.disabled = false;
            });
        });
    }

    /* ---- consult forms ---- */

    function wireConsultForm(form) {
        var status = $('status-message');
        var result = $('result');
        var button = form.querySelector('button[type="submit"]');

        form.addEventListener('submit', function (e) {
            e.preventDefault();
            result.innerHTML = '';

            var params = [];
            new FormData(form).forEach(function (value, key) {
                if (value !== '') {
                    params.push(encodeURIComponent(key) + '=' + encodeURIComponent(value));
                }
            });
            var path = form.dataset.consultEndpoint + (params.length ? '?' + params.join('&') : '');

            setStatus(status, 'Searching...', '');
            button.disabled = true;

            api(path, { method: 'GET' }).then(function (r) {
                if (!r.ok) {
                    setStatus(status, 'Error (HTTP ' + r.status + ')', 'error');
                    result.appendChild(jsonBox(r.data));
                    return;
                }
                var record = r.data[form.dataset.recordKey];
                if (Array.isArray(record)) {
                    if (record.length === 0) {
                        setStatus(status, 'No records found.', '');
                        return;
                    }
                    setStatus(status, record.length + ' record(s) found (HTTP ' + r.status + ')', 'success');
                    record.forEach(function (rec) { result.appendChild(recordTable(rec)); });
                } else {
                    setStatus(status, 'Found (HTTP ' + r.status + ')', 'success');
                    result.appendChild(recordTable(record));
                }
            }).catch(function (err) {
                setStatus(status, 'Could not reach the application tier: ' + err.message, 'error');
            }).finally(function () {
                button.disabled = false;
            });
        });
    }

    document.addEventListener('DOMContentLoaded', function () {
        document.querySelectorAll('form[data-entry-endpoint]').forEach(wireEntryForm);
        document.querySelectorAll('form[data-consult-endpoint]').forEach(wireConsultForm);
    });
})();
