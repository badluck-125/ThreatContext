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

    /* Columns never editable through the modify form. */
    var READONLY_FIELDS = ['id', 'date_added', 'date_modified'];

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
                // Distinguish a fresh record from a replaced one.
                var verb = (r.data && r.data.updated) ? 'Updated' : 'Saved';
                setStatus(status, r.ok ? verb + ' (HTTP ' + r.status + ')' : 'Error (HTTP ' + r.status + ')', r.ok ? 'success' : 'error');
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
        var lastQuery = '';

        /* Delete button rendered with each record when the form
         * declares data-delete-endpoint. data-delete-param names the
         * record field holding the value the endpoint expects
         * (cve_id, exploit_id, ioc_id or the internal id). */
        function deleteButton(rec) {
            var key = form.dataset.deleteParam || 'id';
            var value = rec[key];
            var btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'delete-button';
            btn.textContent = 'Delete';
            btn.addEventListener('click', function () {
                if (value === undefined || value === null || value === '') {
                    setStatus(status, 'Cannot delete: record has no ' + key + '.', 'error');
                    return;
                }
                if (!window.confirm('Delete this record (' + key + ' = ' + value + ')?')) { return; }
                setStatus(status, 'Deleting...', '');
                btn.disabled = true;
                api(form.dataset.deleteEndpoint + '?' +
                    encodeURIComponent(key) + '=' + encodeURIComponent(value),
                    { method: 'DELETE' }
                ).then(function (r) {
                    if (!r.ok) {
                        setStatus(status, 'Delete failed (HTTP ' + r.status + ')', 'error');
                        btn.disabled = false;
                        return;
                    }
                    setStatus(status, 'Deleted (HTTP ' + r.status + ')', 'success');
                    run(lastQuery);          // refresh the current view
                }).catch(function (err) {
                    setStatus(status, 'Could not reach the application tier: ' + err.message, 'error');
                    btn.disabled = false;
                });
            });
            return btn;
        }

        /* Modify button rendered with each record when the form
         * declares data-update-endpoint. First click turns the
         * record table into an editable form (current values as
         * defaults); the next click on the same button validates
         * and POSTs only the changed fields to the update endpoint
         * (internal id sent as ?id=). */
        function modifyButton(rec, item) {
            var btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'modify-button';
            btn.textContent = 'Modify';
            var editing = false;

            btn.addEventListener('click', function () {
                if (!editing) {
                    var table = item.querySelector('table.record-table');
                    if (table) { item.replaceChild(editForm(rec), table); }
                    editing = true;
                    btn.textContent = 'Validate';
                    return;
                }

                /* Validate: send only the fields the user changed. */
                var payload = {};
                var problem = '';
                item.querySelectorAll('[data-field]').forEach(function (field) {
                    if (problem) { return; }
                    if (field.value === field.dataset.original) { return; }
                    var key = field.dataset.field;
                    if (key === 'exploit_id' || key === 'ioc_id') {
                        var n = parseInt(field.value, 10);
                        if (isNaN(n) || String(n) !== field.value.trim()) {
                            problem = key + ' must be an integer.';
                            return;
                        }
                        payload[key] = n;
                    } else if (key === 'point_of_interest') {
                        try {
                            payload[key] = field.value.trim() === ''
                                ? null : JSON.parse(field.value);
                        } catch (err) {
                            problem = 'point_of_interest is not valid JSON: ' + err.message;
                        }
                    } else {
                        payload[key] = field.value;
                    }
                });
                if (problem) { setStatus(status, problem, 'error'); return; }
                if (Object.keys(payload).length === 0) {
                    setStatus(status, 'No change to save.', '');
                    return;
                }

                setStatus(status, 'Saving...', '');
                btn.disabled = true;
                api(form.dataset.updateEndpoint + '?id=' + encodeURIComponent(rec.id), {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                }).then(function (r) {
                    if (!r.ok) {
                        setStatus(status, 'Update failed (HTTP ' + r.status + ')', 'error');
                        result.innerHTML = '';
                        result.appendChild(jsonBox(r.data));
                        btn.disabled = false;
                        return;
                    }
                    setStatus(status, 'Updated (HTTP ' + r.status + ')', 'success');
                    run(lastQuery);          // refresh the current view
                }).catch(function (err) {
                    setStatus(status, 'Could not reach the application tier: ' + err.message, 'error');
                    btn.disabled = false;
                });
            });
            return btn;
        }

        /* Editable copy of a record: every data column becomes an
         * input pre-filled with the current value. The internal id
         * and the dates stay read-only. */
        function editForm(rec) {
            var box = document.createElement('div');
            box.className = 'edit-form';
            Object.keys(rec).forEach(function (key) {
                if (READONLY_FIELDS.indexOf(key) !== -1) { return; }
                var value = rec[key];
                var isJson = value !== null && typeof value === 'object';
                var text = isJson
                    ? JSON.stringify(value, null, 2)
                    : (value === null || value === undefined ? '' : String(value));

                var label = document.createElement('label');
                label.textContent = key;
                var field;
                if (isJson || text.length > 120 || text.indexOf('\n') !== -1) {
                    field = document.createElement('textarea');
                    field.rows = isJson ? 6 : 3;
                } else {
                    field = document.createElement('input');
                    field.type = 'text';
                }
                field.value = text;
                field.dataset.field = key;
                field.dataset.original = text;
                label.appendChild(field);
                box.appendChild(label);
            });
            return box;
        }

        /* One search = one GET on the consult endpoint. With a query
         * it narrows to the requested reference; without a query the
         * endpoint returns every record of the linked table. */
        function run(query) {
            lastQuery = query;
            result.innerHTML = '';
            var path = form.dataset.consultEndpoint + (query ? '?' + query : '');

            setStatus(status, 'Searching...', '');
            button.disabled = true;

            api(path, { method: 'GET' }).then(function (r) {
                if (!r.ok) {
                    setStatus(status, 'Error (HTTP ' + r.status + ')', 'error');
                    result.appendChild(jsonBox(r.data));
                    return;
                }
                var record = r.data[form.dataset.recordKey];
                var records = Array.isArray(record) ? record : [record];
                if (records.length === 0) {
                    setStatus(status, 'No records found.', '');
                    return;
                }
                setStatus(status, Array.isArray(record)
                    ? records.length + ' record(s) found (HTTP ' + r.status + ')'
                    : 'Found (HTTP ' + r.status + ')', 'success');
                records.forEach(function (rec) {
                    var item = document.createElement('div');
                    item.className = 'record-item';
                    item.appendChild(recordTable(rec));
                    if (form.dataset.updateEndpoint) {
                        item.appendChild(modifyButton(rec, item));
                    }
                    if (form.dataset.deleteEndpoint) {
                        item.appendChild(deleteButton(rec));
                    }
                    result.appendChild(item);
                });
            }).catch(function (err) {
                setStatus(status, 'Could not reach the application tier: ' + err.message, 'error');
            }).finally(function () {
                button.disabled = false;
            });
        }

        form.addEventListener('submit', function (e) {
            e.preventDefault();
            var params = [];
            new FormData(form).forEach(function (value, key) {
                if (value !== '') {
                    params.push(encodeURIComponent(key) + '=' + encodeURIComponent(value));
                }
            });
            run(params.join('&'));
        });

        // data-load-all="true": list the whole linked table when the
        // page opens, before the user searches for a reference.
        if (form.dataset.loadAll === 'true') {
            run('');
        }
    }

    /* ---- summary page ---- */

    /* Summary form (data-summary="true"): one cve_id in, a digest of
     * tab_cve, tab_exploit, tab_sample and tab_ioc out. Assembled
     * purely from the existing consult endpoints, no dedicated API:
     *   - cve-consult?cve_id=...        -> every tab_cve row
     *   - exploit-consult?exploit_id=... -> once per unique exploit_id
     *   - sample-consult?platform=...   -> once per unique platform
     *   - ioc-consult?ioc_id=...        -> one block per cve_id/ioc_id
     *                                      couple (every tab_cve row) */
    function pick(record, fields) {
        var out = {};
        fields.forEach(function (f) { out[f] = record[f]; });
        return out;
    }

    function sectionTitle(text) {
        var h = document.createElement('h3');
        h.className = 'summary-title';
        h.textContent = text;
        return h;
    }

    function summaryBlock(records, fields, emptyText) {
        var box = document.createElement('div');
        box.className = 'summary-section';
        if (records.length === 0) {
            var p = document.createElement('p');
            p.className = 'summary-empty';
            p.textContent = emptyText;
            box.appendChild(p);
            return box;
        }
        records.forEach(function (rec) {
            var item = document.createElement('div');
            item.className = 'record-item';
            item.appendChild(recordTable(pick(rec, fields)));
            box.appendChild(item);
        });
        return box;
    }

    function wireSummaryForm(form) {
        var status = $('status-message');
        var result = $('result');
        var button = form.querySelector('button[type="submit"]');

        form.addEventListener('submit', function (e) {
            e.preventDefault();
            result.innerHTML = '';
            var cve_id = form.querySelector('[name="cve_id"]').value.trim();
            if (cve_id === '') { setStatus(status, 'Enter a cve_id.', 'error'); return; }

            setStatus(status, 'Loading summary...', '');
            button.disabled = true;

            api('cve-consult?cve_id=' + encodeURIComponent(cve_id), { method: 'GET' })
                .then(function (r) {
                    if (!r.ok) {
                        setStatus(status, 'Error (HTTP ' + r.status + ')', 'error');
                        result.appendChild(jsonBox(r.data));
                        return;
                    }
                    var rows = r.data.cve || [];

                    // Unique references across all tab_cve rows.
                    var exploitIds = [], platforms = [], iocIds = [];
                    rows.forEach(function (row) {
                        if (row.exploit_id && exploitIds.indexOf(row.exploit_id) === -1) { exploitIds.push(row.exploit_id); }
                        if (row.platform && platforms.indexOf(row.platform) === -1) { platforms.push(row.platform); }
                        if (row.ioc_id && iocIds.indexOf(row.ioc_id) === -1) { iocIds.push(row.ioc_id); }
                    });

                    // One GET per reference; a missing linked record or a
                    // network hiccup on one call never breaks the page,
                    // the section just shows fewer blocks.
                    var calls = [];
                    exploitIds.forEach(function (id) {
                        calls.push(
                            api('exploit-consult?exploit_id=' + encodeURIComponent(id), { method: 'GET' })
                                .then(function (r) { return r.ok ? [r.data.exploit] : []; })
                                .catch(function () { return []; })
                        );
                    });
                    platforms.forEach(function (p) {
                        calls.push(
                            api('sample-consult?platform=' + encodeURIComponent(p), { method: 'GET' })
                                .then(function (r) { return r.ok ? (r.data.samples || []) : []; })
                                .catch(function () { return []; })
                        );
                    });
                    iocIds.forEach(function (id) {
                        calls.push(
                            api('ioc-consult?ioc_id=' + encodeURIComponent(id), { method: 'GET' })
                                .then(function (r) { return r.ok ? [r.data.ioc] : []; })
                                .catch(function () { return []; })
                        );
                    });

                    return Promise.all(calls).then(function (groups) {
                        var nExp = exploitIds.length, nSmp = platforms.length;
                        var merge = function (list) {
                            return list.reduce(function (acc, g) { return acc.concat(g); }, []);
                        };
                        var exploits = merge(groups.slice(0, nExp));
                        var samples  = merge(groups.slice(nExp, nExp + nSmp));
                        var iocs     = merge(groups.slice(nExp + nSmp));

                        setStatus(status, 'Summary for ' + cve_id + ' (HTTP ' + r.status + ')', 'success');
                        result.appendChild(sectionTitle('CVE'));
                        result.appendChild(summaryBlock(rows, ['cve_id'], ''));
                        result.appendChild(sectionTitle('Exploit'));
                        result.appendChild(summaryBlock(exploits,
                            ['exploit_id', 'exploit_type', 'exploit_source'],
                            'No exploit linked to ' + cve_id + '.'));
                        result.appendChild(sectionTitle('Samples'));
                        result.appendChild(summaryBlock(samples,
                            ['platform', 'title', 'sample_source'],
                            'No sample stored for the platform(s) of ' + cve_id + '.'));
                        result.appendChild(sectionTitle('IoC'));
                        result.appendChild(summaryBlock(iocs,
                            ['ioc_id', 'ioc_type', 'ioc_content'],
                            'No IoC linked to ' + cve_id + '.'));
                    });
                })
                .catch(function (err) {
                    setStatus(status, 'Could not reach the application tier: ' + err.message, 'error');
                })
                .finally(function () {
                    button.disabled = false;
                });
        });
    }

    document.addEventListener('DOMContentLoaded', function () {
        document.querySelectorAll('form[data-entry-endpoint]').forEach(wireEntryForm);
        document.querySelectorAll('form[data-consult-endpoint]').forEach(wireConsultForm);
        document.querySelectorAll('form[data-summary]').forEach(wireSummaryForm);
    });
})();
